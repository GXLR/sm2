//
//  CommunicationSecurityConfig.m
//  Tiny
//
//  Created by 徐涛 on 2018/11/20.
//  Copyright © 2018 xiangfp. All rights reserved.
//

#import "CommunicationSecurityConfig.h"

#include <openssl/dh.h>
#import <openssl/err.h>
#import <openssl/ssl.h>

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/bn.h>
#include <openssl/rand.h>  //实现了伪随机数生成，支持用户自定义随机数生成
#include <openssl/dh.h>

#define SPubRSAKey  @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCf/c5HudYApZKVMAyAthM5/eUQ9RGFdnelV6UTynkvqmSi+K6PUtrhyqVnny2Ywkc6ioWgCu953za5JN7NpK4dOmtR2lAtYceSUhNsFSpAit/I0v5Gsn6DG97uko0yzTz1MCViM4fqo+uKN/W9UwNzrsu2e66qA1Or0mNqa3Q8BwIDAQAB"
#define kRSA_KEY_SIZE 1024
#define securityUrlPath   @"/tiny_sys_rsa_exchange.tml"

static CommunicationSecurityConfig* _instance = nil;

@interface CommunicationSecurityConfig ()
{
    RSA *publicKey;
    RSA *privateKey;
}


//AES 最终用于加密的AES 参数 key  IV  由shareKey MD5加密后 的前16位和后16位产生
@property(nonatomic,strong)NSString *AESKey;
@property(nonatomic,strong)NSString *AESVI;


@property(nonatomic,strong)NSString *pubKeyC;//客户端k公钥Client
@property(nonatomic,strong)NSString *privKeyC;//客户端k公钥
//@property(nonatomic,strong)NSString *pubKeyS;//服务端返回公钥

@property(nonatomic,strong)NSString *perAeskey8;//前8位
@property(nonatomic,strong)NSString *perAesiv8;//前偏移量
@property(nonatomic,strong)NSString *lastAeskey8;//后8位
@property(nonatomic,strong)NSString *lastAesiv8;//后偏移量



//
@property(nonatomic,strong)NSString *baseUrl;

@end

//头信息header: data
//
//data = base64( rsa(key8 + iv8 + base64(publickey)))
//
//其中 publickey :base64编码过得本地生成公钥
//
//data 最后统一对 key8+iv8+publickey rsa加密后再base64编码下


@implementation CommunicationSecurityConfig{
    
    SecKeyRef publicKeyRef; //公钥
    SecKeyRef privateKeyRef;//私钥
    
    DH         *dh;
    
}


+(instancetype) shareInstance
{
    static dispatch_once_t onceToken ;
    dispatch_once(&onceToken, ^{
        _instance = [[super allocWithZone:NULL] init] ;
    }) ;
    return _instance ;
}

+(id) allocWithZone:(struct _NSZone *)zone
{
    return [CommunicationSecurityConfig shareInstance] ;
}


-(id) copyWithZone:(struct _NSZone *)zone
{
    return [CommunicationSecurityConfig shareInstance] ;
}

-(id) mutablecopyWithZone:(NSZone *)zone
{
    return [CommunicationSecurityConfig shareInstance] ;
}


-(void)dealloc{
    
    NSLog(@"%@dealloc",[self class]);
}


#pragma Mark  Support  methods


static const NSString *kRandomAlphabet = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

- (NSString *)randomString:(NSInteger)length {
    NSMutableString *randomString = [NSMutableString stringWithCapacity:length];
    for (int i = 0; i < length; i++) {
        [randomString appendFormat: @"%C", [kRandomAlphabet characterAtIndex:arc4random_uniform((u_int32_t)[kRandomAlphabet length])]];
    }
    NSLog(@"randomString = %@", randomString);
    return randomString;
}




//-(void)DHInit{
//     int    ret,size,i,len1,len2;
//    NSString *pStr=@"12315447439826865051139963002157916514233055005227699770728594167666867922943312051152065803618415612675739946437895186185610030299508017481270493681210103";
//    NSString *gStr=@"5";
//    dh = DH_new();
//    BIGNUM *p = bigNumberFromDecimalString(pStr);
//    dh->p = p;
//
//    BIGNUM *g = bigNumberFromDecimalString(gStr);
//    dh->g = g;
//
//    ret=DH_generate_key(dh);
//    if(ret!=1)
//    {
//        printf("DH_generate_key err!\n");
//
//        return;
//    }
//    NSData *publicKeyCData= dataFromBigNumber(dh->pub_key);
//     NSData *privateKeyCData= dataFromBigNumber(dh->priv_key);
//
//    NSString *publicKey64= [publicKeyCData base64EncodedStringWithOptions:0];
//    NSString *privateKey64= [privateKeyCData base64EncodedStringWithOptions:0];
//    NSString *pubcNum=decimalStringFromBigNumber(dh->pub_key);
//     NSString *privateNum=decimalStringFromBigNumber(dh->priv_key);
//    NSLog(@"pubC64=%@ \n pubcNum=%@ \n privateKey64==%@  \n privateNum=%@",publicKey64,pubcNum,privateKey64,privateNum);
//
//}


//DH 算出共同秘钥
//- (NSString *)computeSharedSecretKeyWithOtherPartyPublicKey:(NSData *)otherPartyKey error:(NSError **)error{
//
//    BIGNUM *pub_key = bigNumberFromData(otherPartyKey);
//
//    //Dynamically allocate required bytes
//    unsigned char *computedKey = malloc(DH_size(dh));
//    int size = DH_compute_key(computedKey, pub_key, dh);
//
//    if (size  == -1) {
//        unsigned long errorCode = ERR_get_error();
//
//        SSL_load_error_strings();
//
//        char errorString[1000];
//        char *errorStringDetail = ERR_error_string(errorCode, errorString);
//
//        NSString *message = [NSString stringWithCString:errorStringDetail encoding:NSASCIIStringEncoding];
//        if (error != NULL) {
//            //TODO : Fix the error getting Nil
//            *error = [NSError errorWithDomain:@"DiffieHellman" code:1002 userInfo:@{NSLocalizedDescriptionKey : message}];
//        }
//        return nil;
//    }
////    for(NSInteger i=0;i<computedKey.count;i++){
////
////    }
//    NSString *kk=[self parseByte2HexString:computedKey];
//    NSData* computedSecretKey = [[NSData alloc] initWithBytesNoCopy:computedKey length:size freeWhenDone:YES];
//    NSString *tt= [computedSecretKey base64EncodedStringWithOptions:0];
//    NSLog(@"计算出的  commC= %@",tt);
//    return tt;
//}



-(NSString *) parseByte2HexString:(Byte *) bytes
{
         NSMutableString *hexStr = [[NSMutableString alloc]init];
         int i = 0;
        if(bytes)
           {
                   while (bytes[i] != '\0')
                       {
                           NSLog(@"adjsl9池  %d",i);
                               NSString *hexByte = [NSString stringWithFormat:@"%x",bytes[i] & 0xff];///16进制数
                                if([hexByte length]==1)
                                    [hexStr appendFormat:@"0%@", hexByte];
                                else
                                        [hexStr appendFormat:@"%@", hexByte];
                    
                                i++;
                            }
               if (bytes[i] == '\0') {
                   NSLog(@"badjsh斯柯达旯摸");
               }
               }
       NSLog(@"bytes 的16进制数为:%@",hexStr);
        return hexStr;
     }



-(NSString *)aesKey{
    unsigned char result[16] = {0x73, 0x75, 0x6E, 0x6C, 0x69, 0x6E, 0x65, 0x63, 0x69, 0x6D, 0x62, 0x61, 0x67, 0x65, 0x6E, 0x74};
    NSString *str = [NSString stringWithFormat:
                     @"%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",
                     result[0], result[1], result[2], result[3],
                     result[4], result[5], result[6], result[7],
                     result[8], result[9], result[10], result[11],
                     result[12], result[13], result[14], result[15]
                     ];
    return str;
}

-(NSString *)aesIV{
    unsigned char result[16] = {0x30, 0x31, 0x32, 0x33,0x34,0x35, 0x36, 0x37, 0x38, 0x39, 0x31, 0x32, 0x33, 0x34, 0x35,0x36};
    NSString *str = [NSString stringWithFormat:
                     @"%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",
                     result[0], result[1], result[2], result[3],
                     result[4], result[5], result[6], result[7],
                     result[8], result[9], result[10], result[11],
                     result[12], result[13], result[14], result[15]
                     ];
    return str;
}

BIGNUM * bigNumberFromDecimalString(NSString *string){
    const char *cString = [string cStringUsingEncoding:NSASCIIStringEncoding];
    
    BIGNUM *bn = BN_new();
    BN_dec2bn(&bn, cString);
    return bn;
}

BIGNUM * bigNumberFromData(NSData *data){
    return BN_bin2bn(data.bytes, (int)data.length, NULL);
}


NSString * decimalStringFromBigNumber(BIGNUM *bn){
    char *prime  = BN_bn2dec(bn);
    NSString *string = [[NSString alloc] initWithCString:prime encoding:NSASCIIStringEncoding];
    return string;
}
NSData * dataFromBigNumber(BIGNUM *bn){
    
    
    unsigned char *sBuffer;
    
    NSUInteger aLength = BN_num_bytes(bn);
    
    sBuffer = calloc(1, aLength);
    BN_bn2bin(bn, sBuffer);
    
    return [NSData dataWithBytesNoCopy:sBuffer length:aLength freeWhenDone:YES];
}

/*实现openssl 提供的默认的DH_METHOD，实现了根据密钥参数生成DH公私
 钥，以及根据DH 公钥(一方)以及DH 私钥(另一方)来生成一个共享密钥，用于密
 钥交换*/



static int generate_key(DH *dh);
static int compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);
static int dh_bn_mod_exp(const DH *dh, BIGNUM *r,
                         const BIGNUM *a, const BIGNUM *p,
                         const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx); //r=a^p % m
static int dh_init(DH *dh);
static int dh_finish(DH *dh);

int DH_generate_key(DH *dh)      //生成公私钥
{
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(dh->meth->flags & DH_FLAG_FIPS_METHOD)
        && !(dh->flags & DH_FLAG_NON_FIPS_ALLOW)) {
        DHerr(DH_F_DH_GENERATE_KEY, DH_R_NON_FIPS_METHOD);
        return 0;
    }
#endif
    return dh->meth->generate_key(dh); //生成公私钥，存放于dh结构体的公私钥属性中
}
//根据对方公钥和己方DH 密钥来生成共享密钥的函数
int DH_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(dh->meth->flags & DH_FLAG_FIPS_METHOD)
        && !(dh->flags & DH_FLAG_NON_FIPS_ALLOW)) {
        DHerr(DH_F_DH_COMPUTE_KEY, DH_R_NON_FIPS_METHOD);
        return 0;
    }
#endif
    return dh->meth->compute_key(key, pub_key, dh);   //结果保存在key中
}

int DH_compute_key_padded(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
    int rv, pad;
    rv = dh->meth->compute_key(key, pub_key, dh);
    if (rv <= 0)
        return rv;
    pad = BN_num_bytes(dh->p) - rv;  //返回dh->p的字节数
    if (pad > 0) {
        memmove(key + pad, key, rv);
        memset(key, 0, pad);
    }
    return rv + pad;
}

static DH_METHOD dh_ossl = {
    "OpenSSL DH Method",
    generate_key,
    compute_key,
    dh_bn_mod_exp,
    dh_init,
    dh_finish,
    0,
    NULL,
    NULL
};

const DH_METHOD *DH_OpenSSL(void)
{
    return &dh_ossl;
}

static int generate_key(DH *dh)   //被DH_generate_key调用，这里具体实现
{
    int ok = 0;
    int generate_new_key = 0;
    unsigned l;
    BN_CTX *ctx;  //新建上下文结构
    BN_MONT_CTX *mont = NULL;
    BIGNUM *pub_key = NULL, *priv_key = NULL;
    
    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    
    if (dh->priv_key == NULL) {
        priv_key = BN_new();  //获取私钥
        if (priv_key == NULL)
            goto err;
        generate_new_key = 1;
    } else
        priv_key = dh->priv_key;
    
    if (dh->pub_key == NULL) {
        pub_key = BN_new();  //获取公钥，暂时的
        if (pub_key == NULL)
            goto err;
    } else
        pub_key = dh->pub_key;
    
    if (dh->flags & DH_FLAG_CACHE_MONT_P) {
        mont = BN_MONT_CTX_set_locked(&dh->method_mont_p,
                                      CRYPTO_LOCK_DH, dh->p, ctx);
        if (!mont)
            goto err;
    }
    
    if (generate_new_key) {
        if (dh->q) {
            do {
                if (!BN_rand_range(priv_key, dh->q))//确保priv_key<dh->q
                    goto err;
            }
            while (BN_is_zero(priv_key) || BN_is_one(priv_key));
        } else {
            /* secret exponent length */
            l = dh->length ? dh->length : BN_num_bits(dh->p) - 1;
            if (!BN_rand(priv_key, l, 0, 0))
                goto err;
        }
    }
    
    {
        BIGNUM local_prk;
        BIGNUM *prk;
        
        if ((dh->flags & DH_FLAG_NO_EXP_CONSTTIME) == 0) {
            BN_init(&local_prk);
            prk = &local_prk;
            BN_with_flags(prk, priv_key, BN_FLG_CONSTTIME);
        } else
            prk = priv_key;
        //真正产生公钥
        if (!dh->meth->bn_mod_exp(dh, pub_key, dh->g, prk, dh->p, ctx, mont))
            goto err;
    }
    
    dh->pub_key = pub_key;   //将公私钥赋值到dh结构
    dh->priv_key = priv_key;
    ok = 1;
err:
    if (ok != 1)
        DHerr(DH_F_GENERATE_KEY, ERR_R_BN_LIB);
    
    if ((pub_key != NULL) && (dh->pub_key == NULL))
        BN_free(pub_key);
    if ((priv_key != NULL) && (dh->priv_key == NULL))
        BN_free(priv_key);
    BN_CTX_free(ctx);
    return (ok);
}
//被DH_compute_key调用，这里具体实现
static int compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
    BN_CTX *ctx = NULL;
    BN_MONT_CTX *mont = NULL;
    BIGNUM *tmp;
    int ret = -1;
    int check_result;
    
    if (BN_num_bits(dh->p) > OPENSSL_DH_MAX_MODULUS_BITS) {
        DHerr(DH_F_COMPUTE_KEY, DH_R_MODULUS_TOO_LARGE);
        goto err;
    }
    
    ctx = BN_CTX_new();  //新建上下文结构
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    
    if (dh->priv_key == NULL) {
        DHerr(DH_F_COMPUTE_KEY, DH_R_NO_PRIVATE_VALUE);
        goto err;
    }
    
    if (dh->flags & DH_FLAG_CACHE_MONT_P) {
        mont = BN_MONT_CTX_set_locked(&dh->method_mont_p,
                                      CRYPTO_LOCK_DH, dh->p, ctx);
        if ((dh->flags & DH_FLAG_NO_EXP_CONSTTIME) == 0) {
            /* XXX */
            BN_set_flags(dh->priv_key, BN_FLG_CONSTTIME);
        }
        if (!mont)
            goto err;
    }
    
    if (!DH_check_pub_key(dh, pub_key, &check_result) || check_result) {//检查公钥合理性
        DHerr(DH_F_COMPUTE_KEY, DH_R_INVALID_PUBKEY);
        goto err;
    }
    
    if (!dh->
        //tep=pub_key ^ dh->priv_key % dh->p，tmp就是key
        meth->bn_mod_exp(dh, tmp, pub_key, dh->priv_key, dh->p, ctx, mont)) {
        DHerr(DH_F_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }
    
    ret = BN_bn2bin(tmp, key); //转换为字节存储方式：大端法，存入key中
err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (ret);
}

static int dh_bn_mod_exp(const DH *dh, BIGNUM *r,
                         const BIGNUM *a, const BIGNUM *p,
                         const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    /*
     * If a is only one word long and constant time is false, use the faster
     * exponenentiation function.
     */
    if (a->top == 1 && ((dh->flags & DH_FLAG_NO_EXP_CONSTTIME) != 0)) {
        BN_ULONG A = a->d[0];
        return BN_mod_exp_mont_word(r, A, p, m, ctx, m_ctx);
    } else
        return BN_mod_exp_mont(r, a, p, m, ctx, m_ctx);
}

static int dh_init(DH *dh) //初始化函数
{
    dh->flags |= DH_FLAG_CACHE_MONT_P;
    return (1);
}

static int dh_finish(DH *dh)  //结束函数
{
    if (dh->method_mont_p)
        BN_MONT_CTX_free(dh->method_mont_p);
    return (1);
}


@end
