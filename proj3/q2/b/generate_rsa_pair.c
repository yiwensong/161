#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

int my_better_rand_bytes(unsigned char *buf, int num_bytes);

int main (int argc, char *argv[])
{

    // Normal house keeping
    char *priv_key_file = "q2b_privkey.priv";
    char *pub_key_file = "q2b_pubkey.pub";
    FILE *fp;
    int num_bits = 2048; 

    // This is a recommend public exponent everyone uses. 65537.
    unsigned long exponent = RSA_F4; 
                               
    // Those openssl guys are CHUMPS. Did you see that debian bug? What the
    // heck.  I don't trust them, I'm going to write my own random
    // implementation.  That way I know it will be secure.
    
    // Hmm, in openssl lingo the way you generate random numbers is with a
    // RAND_METHOD Looks like I need to create my own RAND_METHOD structure. It
    // has a bunch of stuff in it, but the only really important parts are the
    // pseudrand and rand members. 
    RAND_METHOD my_better_random_method;

    // Part of the house keeping is I need to clear the struct
    memset(&my_better_random_method, 0x00, sizeof(RAND_METHOD));

 
    // From the openssl man pages it looks liked I need to set two key functions:
    //  pseudorand which behaves like RAND_pseudo_bytes, and
    //  bytes which behaves like RAND_bytes.
    //  man page: http://linux.die.net/man/3/rand_bytes
    // In my implementation, all bytes are pseudorandom, so these are the same
    my_better_random_method.pseudorand = my_better_rand_bytes;
    my_better_random_method.bytes = my_better_rand_bytes;
   
    // Okies I built my random method, now I just need tell openssl to use it 
    RAND_set_rand_method(&my_better_random_method);

    fp = fopen("server_pubkey.pub", "r");
    RSA *srv_key = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);

    for (int i = 0; i < 7812; ++i) {
        srand(i);
        RSA *rsa = RSA_generate_key(num_bits,exponent,NULL,NULL);

        if (BN_cmp(rsa->n, srv_key->n) == 0) {
            if (!(fp = fopen(priv_key_file, "w"))){
                fprintf(stderr, "Could not open private key file %s\n", priv_key_file);
                exit(1);
            }
            
            // openssl has this handy function to write out our private key in the correct format. Awesome.
            if (!PEM_write_RSAPrivateKey(   fp,                     // Output file
                                            rsa,                    // Our private key
                                            NULL,NULL,0,NULL,NULL   // Houekeeping
                                        )
            ){
                fprintf(stderr, "Could not write private key file %s\n", priv_key_file);
                exit(1);
            }
            fclose(fp);
            
            // Write out the public key
            if (!(fp = fopen(pub_key_file, "w"))){
                fprintf(stderr, "Could not open public key file %s\n", pub_key_file);
                exit(1);
            }

            // Just like the private key, the public key can be written by openssl
            if (!PEM_write_RSAPublicKey(fp, rsa))
            {
                fprintf(stderr, "Could not write public key file %s\n", pub_key_file);
                exit(1);
            }
            fclose(fp);
            break;
        }
    }
    
    // OpenSSL has a corresponding read function, it looks like: PEM_read_RSAPublicKey
    exit(0); // Security Success!

}

// K&R are awesome guys. I once got a chance to meet them. I'm sure their
// random number generation is cryptographically secure, given an unguessable
// seed. Let's just use their rand() call.
int my_better_rand_bytes(unsigned char *buf, int num_bytes)
{

    for (int i = 0; i < num_bytes; i+=4)
    {
            int rand_int = rand();
#define min(a,b) (((a)<(b))?(a):(b))
            memcpy(buf + i, &rand_int, min(num_bytes - i,4));
    }
         
    return 1; // 1 means good!
}
