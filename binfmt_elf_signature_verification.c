/*****************************************************************
 *
 * Copyright (C) 2020, Jingtang Zhang, Hua Zong.
 * All Rights Reserved.
 * 
 * binfmt_elf_signature_verification.c
 *
 * Verify the ELF's signature with built-in key-ring. If the
 * signature is correct, return -ENOEXEC to invoke real ELF
 * binary handler; else, return the error code to do_execve()
 * and avoid the ELF being executed.
 * 
 ****************************************************************/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched/mm.h>
#include <linux/magic.h>
#include <linux/binfmts.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/string_helpers.h>
#include <linux/file.h>
#include <linux/pagemap.h>
#include <linux/elf.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#include <linux/verification.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>

/* That's for binfmt_elf_fdpic to deal with */
#ifndef elf_check_fdpic
#define elf_check_fdpic(ex) false
#endif

#if ELF_EXEC_PAGESIZE > PAGE_SIZE
#define ELF_MIN_ALIGN	ELF_EXEC_PAGESIZE
#else
#define ELF_MIN_ALIGN	PAGE_SIZE
#endif

enum verify_signature_e { VPASS, VFAIL, VSKIP };

unsigned char SIG_SCN_SUFFIX[] = "_sig";

#define SCN_CHECKED 1
#define SCN_UNCHECKED 0

/**
 * Check list containing sections whose signature should be verified.
 * Make sure all the sections in check list is verified.
 */
struct scn_checklist {
	unsigned char s_name[8]; /* Section name */
	int s_nlen;              /* Length of section name */
	int s_check;             /* Check status */
};

/**
 * update_checklist()
 *
 * Update the check status of specific section in the check list of
 * all sections whose signature needs to be verified.
 *
 * @scn_cklt: Check list element structure.
 * @cklt_len: Length of check list.
 * @sname: The section name that needs to be updated.
 */
static inline int update_checklist(struct scn_checklist *scn_cklt, int cklt_len,
			unsigned char *sname)
{
	int i, retval = 1;
	for (i = 0; i < cklt_len; i++) {
		if (!memcmp(scn_cklt[i].s_name, sname, scn_cklt[i].s_nlen)) {
			scn_cklt[i].s_check = SCN_CHECKED;
			retval = 0;
			goto out;
		}
	}
out:
	return retval;
}

/**
 * lookup_checklist()
 *
 * Check whether all sections are verified.
 *
 * @scn_cklt: Check list element structure.
 * @cklt_len: Length of check list.
 */
static inline int lookup_checklist(struct scn_checklist *scn_cklt, int cklt_len)
{
	int i, retval = 0;
	for (i = 0; i < cklt_len; i++) {
		if (SCN_UNCHECKED == scn_cklt[i].s_check) {
			printk(" Section '%s' must be signed !\n", scn_cklt[i].s_name);
			retval = 1;
			goto out;
		}
	}
out:
	return retval;
}

#define LD_CACHE_MAGIC_OLD "ld.so-1.7.0"

struct ld_cache_header {
    char magic[sizeof(LD_CACHE_MAGIC_OLD) - 1];
    unsigned int n_libs;
};

struct ld_cache_entry {
    int e_flags;			/* 0x01 indicates ELF library. */
    unsigned int e_key;		/* Key string index. */
    unsigned e_value;		/* Value string index. */
};

/**
 * Metadata structure for holding /etc/ld.so.cache. Only
 * old version of "ld.so-1.7.0" supported currently.
 */
struct ld_so_cache {
	char *l_buf;						/* Cache file content buffer */
	loff_t l_len;						/* Buffer length. */

	unsigned int l_entrynum;			/* Number of cache entries */
	struct ld_cache_entry *l_entries;	/* Start of entry table */
	char *l_strtab;						/* Start of string table */
};

/**
 * init_so_caches()
 * 
 * Open up the dynamic linking cache file in "/etc/ld.so.cache",
 * and read the content into memory buffer. Also, set the pointers
 * to the cache data structures. Meanwhile, do some validation for
 * the cache structure.
 * 
 * @so_cache: an allocated cache metadata structure.
 */
static inline int init_so_caches(struct ld_so_cache *so_cache)
{
	struct file *f_cache = NULL;
	struct ld_cache_header *cache_header;
	void *cursor;
	loff_t pos = 0;
	int retval = 0;

	/* Open up the dynamic linking cache file. */
	f_cache = filp_open("/etc/ld.so.cache", O_RDONLY, 0);
	if (IS_ERR(f_cache)) {
		retval = PTR_ERR(f_cache);
		goto close_file;
	}

	retval = deny_write_access(f_cache);
	if (retval) {
		goto close_file;
	}

	so_cache->l_len = f_cache->f_inode->i_size;

	/* Allocate a memory buffer. */
	so_cache->l_buf = (char *) vmalloc(so_cache->l_len);
	if (!so_cache->l_buf) {
		retval = -ENOMEM;
		goto allow_write;
	}

	/* Read the cache file into memory buffer. */
	retval = kernel_read(f_cache, so_cache->l_buf, so_cache->l_len, &pos);
	if (retval != so_cache->l_len) {
		retval = -EIO;
		goto allow_write;
	}

	printk("%d\n", retval);

	/* Cache header. */
	cursor = so_cache->l_buf;
	cache_header = (struct ld_cache_header *) cursor;
	if (memcmp(cache_header->magic, LD_CACHE_MAGIC_OLD, sizeof(LD_CACHE_MAGIC_OLD) - 1)) {
		retval = -EBADMSG;
		goto allow_write;
	}
	so_cache->l_entrynum = cache_header->n_libs;

	/* Cache entry table. */
	cursor += sizeof(struct ld_cache_header);
	so_cache->l_entries = (struct ld_cache_entry *) cursor;
	/* Cache string table. */
	cursor += so_cache->l_entrynum * sizeof(struct ld_cache_entry);
	so_cache->l_strtab = (char *) cursor;

	/* Validity check. */
	if ((char *) so_cache->l_entries - so_cache->l_buf >= so_cache->l_len) {
		retval = -EBADMSG;
		goto allow_write;
	}
	if (so_cache->l_strtab - so_cache->l_buf >= so_cache->l_len) {
		retval = -EBADMSG;
		goto allow_write;
	}
	/* Make sure the string table has an end, avoiding overflow. */
	if ((so_cache->l_buf)[so_cache->l_len - 1] != '\0') {
		retval = -EBADMSG;
		goto allow_write;
	}

	printk("Cache init done.\n");

	retval = 0; /* Cache initialization done. */
	goto allow_write;

ret:
	return retval;

allow_write:
	allow_write_access(f_cache);
close_file:
	filp_close(f_cache, NULL);
	goto ret;
}

/**
 * cleanup_so_caches()
 * 
 * Free the memory buffer for dynamic linking cache.
 * 
 * @so_cache: an allocated cache metadata structure.
 */
static inline void cleanup_so_caches(struct ld_so_cache *so_cache)
{
	if (so_cache->l_buf) {
		vfree(so_cache->l_buf);
	}
	kfree(so_cache);
}

/**
 * get_so_file_path()
 * 
 * Get the (absolute) file path of .so file through dynamic linking
 * cache. If no path found, return a null-pointer.
 * 
 * @so_cache: an allocated cache metadata structure.
 * @so_key: the name of a .so file, e.g., "libcrypto.so.1.1".
 */
static inline char *get_so_file_path(struct ld_so_cache *so_cache, char *so_key)
{
	struct ld_cache_entry *cache_entry;
	char *str_p;
	int i;

	for (i = 0, cache_entry = so_cache->l_entries;
			i < so_cache->l_entrynum; i++, cache_entry++) {
		str_p = so_cache->l_strtab + cache_entry->e_key;
		if (str_p >= so_cache->l_buf + so_cache->l_len) {
			goto not_found;
		}
		if (!memcmp(so_key, str_p, strlen(str_p))) {
			str_p = so_cache->l_strtab + cache_entry->e_value;
			return str_p >= so_cache->l_buf + so_cache->l_len ? NULL : str_p;
		}
	}

not_found:
	return NULL;
}

/**
 * load_elf_shdrs() - load ELF section headers
 * 
 * Loads ELF section headers from the binary file elf_file, which has the ELF
 * header pointed to by elf_ex, into a newly allocated array. The caller is
 * responsible for freeing the allocated data. Returns an ERR_PTR upon failure.
 * 
 * @elf_ex:   ELF header of the binary whose section headers shold be loaded.
 * @elf_file: the opened ELF binary file.
 */
/*{{{*/	// load_elf_shdrs
static inline struct elf_shdr *load_elf_shdrs(struct elfhdr *elf_ex,
				       struct file *elf_file)
{
	struct elf_shdr *elf_shdata = NULL;
	int retval, size;
	loff_t pos = elf_ex->e_shoff;

	/*
	 * If the size of this structure has changed, then punt, since
	 * we will be doing the wrong thing.
	 */
	if (elf_ex->e_shentsize != sizeof(struct elf_shdr))
		goto out_ret;

	/* Sanity check the number of section headers ... */
	if (elf_ex->e_shnum < 1 ||
		elf_ex->e_shnum > 65536U / sizeof(struct elf_shdr))
		goto out_ret;

	/* ... and their total size. */
	size = sizeof(struct elf_shdr) * elf_ex->e_shnum;
	if (size > ELF_MIN_ALIGN)
		goto out_ret;

	elf_shdata = vmalloc(size);
	if (!elf_shdata)
		goto out_ret;

	/* Read in the section headers */
	retval = kernel_read(elf_file, elf_shdata, size, &pos);
	if (retval != size) {
		vfree(elf_shdata);
		elf_shdata = NULL;
	}

	/* Success! */

out_ret:
	return elf_shdata;
}
/*}}}*/

/**
 * load_elf_sdata() - load ELF section data
 * 
 * Loads ELF section data from the binary file elf_file.
 * 
 * @elf_shdata: ELF section header table.
 * @elf_file: The opened ELF binary file.
 */
/*{{{*/	// load_elf_sdata
static inline unsigned char *load_elf_sdata(struct elf_shdr *elf_shdata, struct file *elf_file)
{
	int size, retval = -EIO;
	unsigned char *elf_sdata = NULL;
	loff_t pos;
	
	/* If the section is empty, return NULL */
	if (SHT_NOBITS == elf_shdata->sh_offset)
		goto out_ret;

	pos = elf_shdata->sh_offset;
	size = elf_shdata->sh_size;
	elf_sdata = vmalloc(size);
	if (!elf_sdata)
		goto out_ret;

	/* Read the secton data into new kernel memory space */
	retval = kernel_read(elf_file, elf_sdata, size, &pos);
	if (retval != size) {
		vfree(elf_sdata);
		elf_sdata = NULL;
	}

	/* Success! */

out_ret:
	return elf_sdata;
}
/*}}}*/

/**
 * scn_name_match() - memory compare for section names.
 * 
 * Firstly, compare the prefix of signed_scn_name and scn_name.
 * If signed_scn_name[prefix] == scn_name[prefix], then compare 
 * the suffix; if signed_scn_name[suffix] == "_sig", comparison pass.
 * 
 * @scn_name: The original section name, e.g. ".text".
 * @scn_name_len: The length of original section name.
 * @signed_scn_name: The signed section name, e.g. ".text_sig".
 * @signed_scn_name_len: The length of signed section name.
 *
 */
/*{{{*/	// scn_name_match
static inline int scn_name_match(unsigned char *scn_name, int scn_name_len,
			unsigned char *signed_scn_name, int signed_scn_name_len)
{
	int retval = 1;
	
	/**
	 * 1. (len(.text_sig) - len(.text)) =? len(_sig)
	 * 2. .text[_sig] =? .text
	 * 3. [.text]_sig =? _sig
	 */
	if ((signed_scn_name_len - scn_name_len) != (sizeof(SIG_SCN_SUFFIX) - 1)) {
		goto out;
	}
	if (memcmp(signed_scn_name, scn_name, scn_name_len)) {
		goto out;
	}
	if (memcmp(signed_scn_name + scn_name_len, SIG_SCN_SUFFIX, sizeof(SIG_SCN_SUFFIX) - 1)) {
		goto out;
	}

	/* Success! */
	retval = 0;
out:
	return retval;
}
/*}}}*/

/*
 * free_bprm()
 * 
 * Free linux_binprm structure.
 *
 */
static inline void free_bprm(struct linux_binprm *bprm)
{
	if (bprm->file) {
		// fput(bprm->file);
		filp_close(bprm->file, NULL);
	}
	/* If a binfmt changed the interp, free it. */
	if (bprm->interp != bprm->filename) {
		kfree(bprm->interp);
	}
	kfree(bprm);
}

/**
 * 
 * verify_scn_signature() - verify the section signature.
 * 
 * Use verify_pkcs7_signature(...) to verify the signature.
 * 
 * @scn_data: Data of original section.
 * @scn_data_len: Length of original section data.
 * @sig_scn_data: Data of signature section.
 * @sig_scn_data_len: Length of signature section data.
 *
 */
/*{{{*/	// verify_scn_signature
static inline int verify_scn_signature(unsigned char *scn_data, int scn_data_len, 
				unsigned char *sig_scn_data, int sig_scn_data_len)
{
	int retval;

	retval = verify_pkcs7_signature(scn_data, scn_data_len,
					sig_scn_data, sig_scn_data_len,
					NULL, VERIFYING_MODULE_SIGNATURE, NULL, NULL);
	printk("verify_pkcs7_signature return value: %d\n", retval);
	return retval;
}
/*}}}*/

static int elf_signature_verification(struct linux_binprm *bprm, struct ld_so_cache *so_cache);

/**
 * so_signature_verification()
 * 
 * Verify the signature of .so dependencies of an ELF
 * file (program OR shared object).
 * 
 * @bprm: the original ELF file handler.
 * @so_cache: the dynamic linking cache.
 * @elf_dynamic: section data of ".dynamic".
 * @e_dynnum: number of ".dynamic" section entries.
 * @elf_dynstr: section data of ".dynstr".
 */
static inline int so_signature_verification(struct linux_binprm *bprm, struct ld_so_cache *so_cache,
		void *elf_dynamic, int e_dynnum, unsigned char *elf_dynstr)
{
	Elf64_Dyn *dyn_ptr;
	char *so_file_path;
	struct linux_binprm *so_bprm;
	struct file *so_file;
	int i, retval = -ENOEXEC;
	loff_t pos = 0;

	// for (dyn_ptr = elf_dynamic, i = 0; i < e_dynnum; dyn_ptr++, i++) {
	// 	if (dyn_ptr->d_tag == DT_NEEDED) {
	// 		printk("Dependency library: %s\n", elf_dynstr + dyn_ptr->d_un.d_val);
	// 		so_file_path = get_so_file_path(so_cache, elf_dynstr + dyn_ptr->d_un.d_val);
	// 		if (so_file_path) {
	// 			printk("%s\n", so_file_path);
	// 		}
	// 	}
	// }

	// return retval;

	for (dyn_ptr = elf_dynamic, i = 0; i < e_dynnum; dyn_ptr++, i++) {
		if (dyn_ptr->d_tag == DT_NEEDED) {
			printk("Dependency library: %s\n", elf_dynstr + dyn_ptr->d_un.d_val);

			/* Get the absolute path of this dynamic lib.so. */
			so_file_path = get_so_file_path(so_cache, elf_dynstr + dyn_ptr->d_un.d_val);
			if (!so_file_path) {
				retval = -ENOENT;
				goto out_ret;
			}

			/* Allocate for a new linux_binprm for shared object file. */
			so_bprm = kzalloc(sizeof(*so_bprm), GFP_KERNEL);
			if (!so_bprm) {
				retval = -ENOMEM;
				goto out_ret;
			}

			/* Open the .so file. */
			so_file = filp_open(so_file_path, O_RDONLY, 0);
			if (IS_ERR(so_file)) {
				retval = PTR_ERR(so_file);
				goto out_free;
			}

			retval = deny_write_access(so_file);
			if (retval) {
				goto out_free;
			}
			
			so_bprm->file = so_file;
			/* Here is a fake check now, we can make sure the filename
			 * is absolute path.
			 */
			if (so_file_path[0] == '/') {
				so_bprm->filename = so_file_path;
			} else {
				so_bprm->filename = so_file_path;
			}
			so_bprm->interp = so_bprm->filename;

			// so_bprm->argc = count(argv, MAX_ARG_STRINGS);
			// if ((retval = so_bprm->argc) < 0)
			// 	goto out;

			// so_bprm->envc = count(envp, MAX_ARG_STRINGS);
			// if ((retval = so_bprm->envc) < 0)
			// 	goto out;

			/* Read the first 128 bytes of the file. */
			retval = kernel_read(so_bprm->file, so_bprm->buf, BINPRM_BUF_SIZE, &pos);
			if (retval != BINPRM_BUF_SIZE) {
				retval = -EIO;
				goto out_allow_write;
			}
			
			/* Verify this lib.so now ! */
			retval = elf_signature_verification(so_bprm, so_cache);
			if (retval != -ENOEXEC)
				goto out_allow_write;

			allow_write_access(so_bprm->file);
			free_bprm(so_bprm);
		}
	}

	goto out_ret;

out_allow_write:
	allow_write_access(so_bprm->file);
out_free:
	free_bprm(so_bprm);
out_ret:
	return retval;
}

/**
 * elf_format_validation()
 * 
 * To check if the file conforms to ELF format, and whether we need to
 * skip the verification. A return value of -ENOEXEC means we will skip
 * the verification, and a zero return value means the file comforms to
 * ELF format and we need to verify its signature.
 * 
 * @bprm: the binary program handler.
 */
static inline int elf_format_validation(struct linux_binprm *bprm)
{
	struct elfhdr *elf_ex;
	int retval = -ENOEXEC; /* Skip verification for default. */

	/**
	 * Skip the verification of system ELF binaries. We use the name of
	 * interpreter instead of the name of file because of:
	 *
	 * https://github.com/NUAA-WatchDog/linux-kernel-elf-sig-verify/pull/13
	 *
	 * ATTENTION: these code can be removed if all built-in ELF binaries
	 *            on system are signed.
	 */
	if (!memcmp(bprm->interp, "/bin/", 5) ||
		(!memcmp(bprm->interp, "/lib/", 5) &&
			memcmp(bprm->interp, "/lib/x86_64-linux-gnu/libtest.so", 32)) ||
		!memcmp(bprm->interp, "/etc/", 5) ||
		!memcmp(bprm->interp, "/sbin/", 6) ||
		!memcmp(bprm->interp, "/usr/", 5) ||
		!memcmp(bprm->interp, "/tmp/", 5) ||
		!memcmp(bprm->interp, "/var/", 5)) {

		printk("Skip for verification of: %s\n", bprm->interp);
		goto out; /* Skip. */
	}

	elf_ex = (struct elfhdr *) bprm->buf;

	/* Not a ELF file, return -ENOEXEC to skip this handler. */
	if (memcmp(elf_ex->e_ident, ELFMAG, SELFMAG) != 0) {
		goto out; /* Skip. */
	}

	/* Here we are sure it is an ELF file. */
	if (ET_EXEC != elf_ex->e_type && ET_DYN != elf_ex->e_type) {
		goto out;
	}
	if (!elf_check_arch(elf_ex)) {
		goto out;
	}
	if (elf_check_fdpic(elf_ex)) {
		goto out;
	}
	if (!bprm->file->f_op->mmap) {
		goto out;
	}
	if (SHN_UNDEF == elf_ex->e_shstrndx) {
		retval = -EBADMSG;
		goto out;
	}

	retval = 0; /* Validation pass. We want to verify this file. */

out:
	return retval;
}

/**
 * elf_signature_verification()
 * 
 * Entry function for verify single ELF file's signature.
 * 
 * @bprm: the binary program handler.
 * @so_cache: the dynamic linking cache.
 */
static int elf_signature_verification(struct linux_binprm *bprm, struct ld_so_cache *so_cache)
{
	enum verify_signature_e verify_e = VSKIP;

	int retval, i, j;
	int elf_slen, elf_sslen;
	int e_dynnum = 0;

	unsigned char *elf_shstrtab, *elf_sdata, *elf_ssdata;
	unsigned char *elf_dynstrtab = NULL, *elf_dynamic = NULL;
	unsigned char *scn_name, *signed_scn_name;
	size_t scn_name_len, signed_scn_name_len;

	struct elfhdr *elf_ex;
	struct elf_shdr *elf_shptr, *elf_shdata;

	/**
	 * Section list that needs to be checked.
	 * Only .text section currently.
	 */
	struct scn_checklist scn_cklt[] = {
		{".text", sizeof(".text") - 1, SCN_UNCHECKED},
		// {".data", 5, 0}
	};

	/**
	 * Validate if it is an ELF file. Skip the verification
	 * if it is not.
	 */
	retval = elf_format_validation(bprm);
	if (retval) {
		if (retval != -ENOEXEC) {
			verify_e = VFAIL;
		}
		goto out_ret;
	}

	/**
	 * The default return value for search_binary_handler() to iterate the 
	 * next binary format's handler. It should be used in three cases:
	 * 
	 * 1. Skip the binary file which is not in ELF format at all.
	 * 2. Skip the verification of an ELF file, let binfmt_elf to execute
	 *    it directly.
	 * 3. The ELF file passes the verification, and should be executed 
	 *    by binfmt_elf normally.
	 */
	retval = -ENOEXEC;

	printk("Start to verify '%s' ...", bprm->interp);

	/**
	 * Get the header of the file to be ELF header, check ELF format 
	 * and do some simple consistency checks.
	 * 
	 * With the information in ELF header, load section header table 
	 * and section header string table into memory, and prepare for
	 * the signature verification.
	 */
	elf_ex = (struct elfhdr *) bprm->buf;

	/* Section header table. */
	elf_shdata = load_elf_shdrs(elf_ex, bprm->file);
	if (!elf_shdata) {
		retval = -ENOMEM;
		goto out_ret;
	}

	/* Section header string table. */
	elf_shptr = elf_shdata + elf_ex->e_shstrndx;
	elf_shstrtab = load_elf_sdata(elf_shptr, bprm->file);
	if (!elf_shstrtab) {
		retval = -ENOMEM;
		goto out_free_shdata;
	}
	
	/**
	 * Iterate over sections, find two sections matched with "_sig" suffix.
	 * 
	 * At the same time, prepare ".dynstr" and ".dynamic" for verification
	 * of shared objects dependencies of dynamic linking.
	 */
	for (i = 0; i < elf_ex->e_shnum; i++) {
		scn_name = elf_shstrtab + (elf_shdata + i)->sh_name;
		scn_name_len = strlen(scn_name);

		/* Prepare ".dynstr" and ".dynamic" section in memory. */
		if (!elf_dynstrtab && !memcmp(".dynstr", scn_name, sizeof(".dynstr") - 1)) {
			elf_dynstrtab = load_elf_sdata(elf_shdata + i, bprm->file);
			if (!elf_dynstrtab) {
				retval = -ENOMEM;
				goto out_free_shdata;
			}
		} else if (!elf_dynamic && !memcmp(".dynamic", scn_name, sizeof(".dynamic") - 1)) {
			elf_dynamic = load_elf_sdata(elf_shdata + i, bprm->file);
			if (!elf_dynamic) {
				retval = -ENOMEM;
				goto out_free_shdata;
			}
			e_dynnum = (elf_shdata + i)->sh_size / sizeof(Elf64_Dyn);
		}

		/** 
		 * Find out the signature sections with suffix '_sig',
		 * then verify the signature.
		 */
		for (j = 0; j < elf_ex->e_shnum; j++) {
			signed_scn_name = elf_shstrtab + (elf_shdata + j)->sh_name;	
			signed_scn_name_len = strlen(signed_scn_name);

			/**
			 * Find out two matched section like:
			 * 		len(".text") < len(".text_sig")
			 * where [i] stand for ".text", [j] stand for ".text_sig".
			 */
			if (scn_name_len >= signed_scn_name_len) {
				continue;
			}
			if (scn_name_match(scn_name, scn_name_len, signed_scn_name, signed_scn_name_len)) {
				continue;
			}

			/* 
			 * Found two sections with matching name, e.g. ".text" and
			 * ".text_sig". Then, load the data of these two sections.
			 */
			printk("Found two matching sections : %s %s\n",
					scn_name, signed_scn_name);

			/* Load the original data section. */
			elf_shptr = elf_shdata + i;
			elf_slen = elf_shptr->sh_size;
			elf_sdata = load_elf_sdata(elf_shptr, bprm->file);
			if (!elf_sdata) {
				retval = -ENOMEM;
				goto out_free_shstrtab;
			}
			
			/* Load the signature data section. */
			elf_shptr = elf_shdata + j;
			elf_sslen = elf_shptr->sh_size;
			elf_ssdata = load_elf_sdata(elf_shptr, bprm->file);
			if (!elf_ssdata) {
				retval = -ENOMEM;
				goto out_free_sdata;
			}

			/* Verify the signature. */
			retval = verify_scn_signature(elf_sdata, elf_slen, elf_ssdata, elf_sslen);
			if (retval) {
				goto out_free_ssdata;
			}

			/* Update check list status. */
			update_checklist(scn_cklt, sizeof(scn_cklt) / sizeof(struct scn_checklist), scn_name);

			/* Clean up and prepare for the next iteration. */
			vfree(elf_sdata);
			vfree(elf_ssdata);
			elf_sdata = NULL;
			elf_ssdata = NULL;
		}
	}
	
	/* Make sure all signature sections are successfully verified. */
	if (!lookup_checklist(scn_cklt, sizeof(scn_cklt) / sizeof(struct scn_checklist))) {
		verify_e = VPASS;
	} else {
		retval = -ENODATA;
		verify_e = VFAIL;
	}
	
	goto out_free_shstrtab;

out_ret:
	/* Start to verify dependencies of shared object. */
	// if (elf_dynamic) {
	// 	if (elf_dynstrtab) {
	// 		if (VPASS == verify_e) {
	// 			retval = so_signature_verification(bprm, elf_dynamic, elf_dynstrtab);
	// 		}
	// 		vfree(elf_dynstrtab);
	// 	}
	// 	vfree(elf_dynamic);
	// }

	if (VPASS == verify_e && elf_dynamic && elf_dynstrtab) {
		retval = so_signature_verification(bprm, so_cache, elf_dynamic, e_dynnum, elf_dynstrtab);
		if (retval != -ENOEXEC) {
			verify_e = VFAIL;
		}
	}

	/* Free the dynamic linking data structure. */
	if (elf_dynamic) {
		vfree(elf_dynamic);
	}
	if (elf_dynstrtab) {
		vfree(elf_dynstrtab);
	}

	if (VPASS == verify_e) {
		printk("Verifying pass ...\n");
		retval = -ENOEXEC;
	} else if (VFAIL == verify_e) {
		printk("Verifying failed ...\n");
	} else {
		retval = -ENOEXEC; /* skipped */
	}

	return retval;
	
out_free_ssdata:
	vfree(elf_ssdata);
out_free_sdata:
	vfree(elf_sdata);
out_free_shstrtab:
	vfree(elf_shstrtab);
out_free_shdata:
	vfree(elf_shdata);
	goto out_ret;
}

/**
 * load_elf_signature_verification_binary()
 * 
 * Interface function for binfmt_xxx.
 * 
 * @bprm: the binary program handler
 */
static int load_elf_signature_verification_binary(struct linux_binprm *bprm)
{
	int retval;
	struct ld_so_cache *so_cache;

	/**
	 * Validatation of ELF format.
	 * 
	 * If the function return 0, it means that it is an ELF file, and we want
	 * to verify its signature; if -ENOEXEC returned, it means that it is not
	 * an ELF file, and we don't verify, skip it; if other errores are returned,
	 * it means that it is an ELF, but it is corrupted, we'll leave it to the
	 * real ELF handler. skip it.
	 */
	retval = elf_format_validation(bprm);
	if (retval) {
		goto out;
	}

	so_cache = (struct ld_so_cache *) kzalloc(sizeof(*so_cache), GFP_KERNEL);
	if (!so_cache) {
		retval = -ENOMEM;
		goto out;
	}
	if ((retval = init_so_caches(so_cache))) {
		goto clean_up;
	}
	
	retval = elf_signature_verification(bprm, so_cache);
	
clean_up:
	cleanup_so_caches(so_cache);
out:
	return retval;
}

/*
 * \brief Register a new handler for signature verification.
 */
static struct linux_binfmt elf_signature_verification_format = {
	.module = THIS_MODULE,
	.load_binary = load_elf_signature_verification_binary,
};

static int __init init_elf_signature_verification_binfmt(void)
{
	insert_binfmt(&elf_signature_verification_format);
	return 0;
}

static void __exit exit_elf_signature_verification_binfmt(void)
{
	unregister_binfmt(&elf_signature_verification_format);
}

module_init(init_elf_signature_verification_binfmt);
module_exit(exit_elf_signature_verification_binfmt);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("mrdrivingduck <mrdrivingduck@gmail.com>");
MODULE_AUTHOR("zonghuaxiansheng <zonghuaxiansheng@outlook.com>");
MODULE_DESCRIPTION("Binary handler for verifying signature in ELF sections");
MODULE_VERSION("1.15");
MODULE_ALIAS("binfmt_elf_signature_verification");
