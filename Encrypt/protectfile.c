#include <stdio.h>
#include <fcntl.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>

#include "rijndael.h"
#define KEYBITS 128

int main(int argc, char **argv)
{
	unsigned long rk[RKLENGTH(KEYBITS)];	/* round key */
	unsigned char key[KEYLENGTH(KEYBITS)];/* cipher key */
	char buf[100];
	int i, nbytes, nwritten, ctr;
	int k0, k1;
	int fileId = 0x1234;
	int nrounds; /* # of Rijndael rounds */
	int	fd;
	int totalbytes;
	char *filename;
	unsigned char filedata[16];
	unsigned char ciphertext[16];
	unsigned char ctrvalue[16];

	if (argc != 5)
	{
		fprintf (stderr, "Usage: %s <-e (encrypt) or -d (decrypt)> <k0> <k1> <file>\n", argv[0]);
		exit (1);
	}
	
	/* Get key from user */
	bzero (key, sizeof(key));
	k0 = strtol (argv[2], NULL, 0);
	k1 = strtol (argv[3], NULL, 0);
	
	bcopy (&k0, &(key[0]), sizeof (k0));
	bcopy (&k1, &(key[sizeof(k0)]), sizeof (k1));
	
	/*Get file from user */
	filename = argv[4];
	
	/* Open the file. */
	fd = open(filename, O_RDWR);
	if (fd < 0)	{ 
		fprintf(stderr, "Error opening file %s\n", argv[4]); 
		exit(1); 
	}
	
	/* Obtain file stats */
	struct stat sb;
	stat (filename, &sb);
	mode_t mode;
	mode = sb.st_mode;
	int sticky_bit_flag = 0;
	
	/* setkey */
	/* Pass in a third argument, pid into setkey */
	/* add k0 and k1 to user */
	int success = syscall(548, k0, k1, sb.st_uid);
	
	/* If setkey returns EPERM, means wrong key was inputted */
	if (success == EPERM) {	
		printf("Wrong key!\n"); 
		exit(1);
	}
	/* If userlist is full, returns -2 */
	else if (success == -2) { 
		printf("User-list is full.\n"); 
		exit(1);
	}
	/* If user inputs 0, 0 it means to unset the key and not encrypt/decrypt */
	if (k0 == 0 && k1 == 0) {
		printf("Key unset.\n");
		exit (1);
	}
	
	if ((mode & S_ISVTX) == S_ISVTX)
		sticky_bit_flag = 1;
	
	char *token = strtok(argv[1], "-");
	
	/* Error checking */
	/* If encrypting, but sticky bit already set, cannot encrypt */
	/* If decrypting, but sticky bit unset, then cannot decrypt */
	if (strcmp(token, "e") == 0 && sticky_bit_flag){ 
		printf("Cannot encrypt an already encrypted file.\n"); 
		exit(1); 
	}
	else if (strcmp(token, "d") == 0 && !sticky_bit_flag){ 
		printf("Cannot decrypt an already decrypted file.\n"); 
		exit(1); 
	}
	
	/* Initialize the Rijndael algorithm.*/
	nrounds = rijndaelSetupEncrypt(rk, key, 128);
	
	/* fileID goes into bytes 8-11 of the ctrvalue */
	bcopy (&fileId, &(ctrvalue[8]), sizeof (fileId));

	/* This loop reads 16 bytes from the file, XORs it with the encrypted
	CTR value, and then writes it back to the file at the same position.
	Note that CTR encryption is nice because the same algorithm does
	encryption and decryption.  In other words, if you run this program
	twice, it will first encrypt and then decrypt the file.
	*/
	for (ctr = 0, totalbytes = 0; /* loop forever */; ctr++)
	{
		/* Read 16 bytes (128 bits, the blocksize) from the file */
		nbytes = read (fd, filedata, sizeof (filedata));
		if (nbytes <= 0) {
			break;
		}
		if (lseek (fd, totalbytes, SEEK_SET) < 0)
		{
			perror ("Unable to seek back over buffer");
			exit (-1);
		}

		/* Set up the CTR value to be encrypted */
		bcopy (&ctr, &(ctrvalue[0]), sizeof (ctr));

		/* Call the encryption routine to encrypt the CTR value */
		rijndaelEncrypt(rk, nrounds, ctrvalue, ciphertext);

		/* XOR the result into the file data */
		for (i = 0; i < nbytes; i++) {
			filedata[i] ^= ciphertext[i];
		}

		/* Write the result back to the file */
		nwritten = write(fd, filedata, nbytes);
		if (nwritten != nbytes)
		{
			fprintf (stderr,
			"%s: error writing the file (expected %d, got %d at ctr %d\n)",
			argv[0], nbytes, nwritten, ctr);
			break;
		}

		/* Increment the total bytes written */
		totalbytes += nbytes;
	}
	
	/* Toggle sticky bit */
	mode = sb.st_mode ^ S_ISVTX;
	chmod(filename, mode);
	
	close (fd);
}
