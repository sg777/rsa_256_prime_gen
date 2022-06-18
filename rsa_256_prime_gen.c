#include<stdio.h>
#include <openssl/bn.h>

void print_pubkey(BIGNUM *e, BIGNUM *n){
	printf("\npubkey(e,n) = ");
	printf("(");
	BN_print_fp(stdout, e);
	printf(",");
	BN_print_fp(stdout, n);
	printf(")");
}

void print_privkey(BIGNUM *d, BIGNUM *n){
	printf("\nprivkey(d,n) = ");
	printf("(");
	BN_print_fp(stdout, d);
	printf(",");
	BN_print_fp(stdout, n);
	printf(")");
	
}	

BIGNUM* bn_lcm(BIGNUM *a, BIGNUM *b){
	BIGNUM *gcd, *product, *lcm, *r;
	BN_CTX *ctx;

	ctx = BN_CTX_new();
	gcd = BN_new();
	product = BN_new();
	lcm = BN_new();
	r = BN_new();

	BN_gcd(gcd,a,b,ctx);
	BN_mul(product,a,b,ctx);
	BN_div(lcm,r,product,gcd,ctx);

	if(BN_is_zero(r) == 0){
		printf("For RSA it should be zero, some error run again\n");
	}
	
	BN_free(gcd);
	BN_free(product);
	BN_free(r);
	BN_CTX_free(ctx);
	
	return lcm;
}

BIGNUM* bn_lambda(BIGNUM *p, BIGNUM *q){ // This function computes the Carmichael's totient
	BIGNUM *pi_p, *pi_q, *lambda_n;

	pi_p = BN_new();
	pi_q = BN_new();
	lambda_n = BN_new();

	pi_p = BN_dup(p);	
	BN_sub_word(pi_p,1);
	pi_q = BN_dup(q);
	BN_sub_word(pi_q,1);
	lambda_n = bn_lcm(pi_p,pi_q);

	BN_free(pi_p);
	BN_free(pi_q);	

	return lambda_n;
}

int check_if_coprime(BIGNUM *a, BIGNUM *b){
	BIGNUM *gcd;
	BN_CTX *ctx; 

	int coprime;
		
	gcd = BN_new();
	ctx = BN_CTX_new();
	BN_gcd(gcd,a,b,ctx);
	
	coprime = BN_is_one(gcd);

	BN_free(gcd);
	BN_CTX_free(ctx);

	return coprime;
}

int main(){
	int prime_size = 128; // For an RSA of 256 bit keys we need two primes of size 128 bits.
	BIGNUM *p, *q, *n, *e, *d, *lambda_n;	
	BN_CTX *ctx;

	ctx = BN_CTX_new();
	p = BN_new();
	q = BN_new();

	n = BN_new();
	e = BN_new();
	d = BN_new();

	BN_set_word(e, 65537);

	BN_generate_prime_ex(p, prime_size, 0, NULL, NULL, NULL);
	BN_generate_prime_ex(q, prime_size, 0, NULL, NULL, NULL);

	BN_mul(n,p,q,ctx);
	lambda_n = bn_lambda(p,q);

	if(check_if_coprime(e,lambda_n) == 0) {
		printf("\n e and lambda_n are not co prime, run again");
		goto end;
	}

	BN_mod_inverse(d, e, lambda_n, ctx);
	printf("All values are displayed in HEX");
	print_pubkey(e,n);
	print_privkey(d,n);
	printf("\n");
	
	BN_free(p);
	BN_free(q);
	BN_free(n);
	BN_free(e);
	BN_free(d);
	BN_free(lambda_n);
	BN_CTX_free(ctx);

	end:
		return 0;
}
