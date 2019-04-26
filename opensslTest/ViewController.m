//
//  ViewController.m
//  opensslTest
//
//  Created by LANGE on 2019/1/16.
//  Copyright © 2019年 LANGE. All rights reserved.
//

#import "ViewController.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "internal/sm2.h"
#include "testutil.h"


@interface ViewController (){

}

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    UIButton *jiami = [UIButton buttonWithType:UIButtonTypeCustom];
    jiami.frame = CGRectMake(([UIScreen mainScreen].bounds.size.width - 100) / 2, 100, 100, 100);
    jiami.backgroundColor = [UIColor redColor];
    [jiami setTitle:@"encrypt" forState:UIControlStateNormal];
    [jiami addTarget:self action:@selector(sm2Test) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:jiami];
}

/*
 *SM2算法
 */

- (void)sm2Test {
    
//    genkey();
    
    NSString *miwen = [self sm2Encrypt1:@"04DC7327738C66D01970B40CE2084B7F44FFFF3A90789BEDA407D8B85BCF1296551919B21662EE586444696705AAF85FF7156AC64EC204341EB4FA705E5A551E56" message:@"123456789"];
    
    [self sm2Derypt1:@"7F17B17EABB73E81310D1EC734E30933A5E43096DFB2DA578BA12E3C07DCBABE" message:miwen];
    
}

-(NSString *)sm2Encrypt1:(NSString*)publickey message:(NSString*)data {
    
    NSString *d = nil;
    EC_KEY *ec_key = NULL;
    const char *point;
    const EC_GROUP *sm2group;
    EC_POINT *pub_key;
    const char *message;
    uint8_t *ctext = NULL;
    size_t ctext_len = 0;
    const EVP_MD *digest = EVP_sm3();
    point = [publickey UTF8String];
    message = [data UTF8String];
    const size_t msg_len = strlen(message);
    sm2group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    ec_key = EC_KEY_new();
    EC_KEY_set_group(ec_key, sm2group);
    pub_key = EC_POINT_new(sm2group);
    EC_POINT_hex2point(sm2group, point, pub_key, NULL);
    EC_KEY_set_public_key(ec_key, pub_key);
    sm2_ciphertext_size(ec_key, digest, msg_len, &ctext_len);
    ctext = (uint8_t *) OPENSSL_zalloc(ctext_len);
    int sm2enc = sm2_encrypt(ec_key, digest, (const uint8_t *) message, msg_len, ctext, &ctext_len);
    if (!sm2enc)
    {
        printf("Error Of en calculate cipher text length.\n");
    }
    
    char buffer[1024];//维数定义些
    convertUnCharToStr(buffer, ctext, ctext_len);
    printf("%s\n", buffer);

    d = [[NSString stringWithCString:buffer encoding:NSUTF8StringEncoding]uppercaseString];
    
    EC_POINT_free(pub_key);
    OPENSSL_free(ctext);
    EC_KEY_free(ec_key);
    return d;
}

-(NSString *)sm2Derypt1:(NSString*)privkey message:(NSString*)data {
    
    EC_KEY *ec_key = NULL;
    BIGNUM *prv = NULL;
    const EC_GROUP *sm2group;
    const EVP_MD *digest = EVP_sm3();
    unsigned char *message = OPENSSL_hexstr2buf([data UTF8String], NULL);
    const char *pri = [privkey UTF8String];
    const size_t ctext_len = strlen([data UTF8String]) / 2.0;
    size_t recovered_len = 0;
    uint8_t *recovered = NULL;
    BN_hex2bn(&prv, pri);
    sm2group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    ec_key = EC_KEY_new();
    EC_KEY_set_group(ec_key, sm2group);
    EC_KEY_set_private_key(ec_key, prv);
    sm2_plaintext_size(ec_key, digest, ctext_len, &recovered_len);
    
    recovered = OPENSSL_zalloc(recovered_len);
    int sm2de = sm2_decrypt(ec_key, digest, message, ctext_len, recovered, &recovered_len);
    if (!sm2de)
    {
        printf("Error Of de calculate cipher text length.\n");
    }
    
    printf("crypto function ok %s\n", recovered);


    EC_KEY_free(ec_key);
    OPENSSL_free(recovered);
    return NULL;
}

EC_KEY *genkey()
{
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_KEY *ecKey = EC_KEY_new();
    EC_KEY_set_group(ecKey, group);
    EC_KEY_generate_key(ecKey);
    const EC_POINT *pubkey = EC_KEY_get0_public_key(ecKey);
    const BIGNUM *prikey = EC_KEY_get0_private_key(ecKey);
    char *priout = BN_bn2hex(prikey);
    char *pubout = EC_POINT_point2hex(group, pubkey, POINT_CONVERSION_UNCOMPRESSED, NULL);
    size_t prilen = strlen(priout);
    size_t publen = strlen(pubout);
    char out[prilen+publen];
    strcpy(out,priout);
    strcat(out,pubout);
    
    
    EC_KEY_free(ecKey);
    EC_GROUP_free(group);
    OPENSSL_free(priout);
    OPENSSL_free(pubout);
    
    return NULL;
}

void convertUnCharToStr(char* str, unsigned char* UnChar, int ucLen)
{
    int i = 0;
    for(i = 0; i < ucLen; i++)
    {
        //格式化输str,每unsigned char 转换字符占两位置%x写输%X写输
        sprintf(str + i * 2, "%02x", UnChar[i]);
    }
}

void convertStrToUnChar(char* str, unsigned char* UnChar)
{
    int i = strlen(str), j = 0, counter = 0;
    char c[2];
    unsigned int bytes[2];
    
    for (j = 0; j < i; j += 2)
    {
        if(0 == j % 2)
        {
            c[0] = str[j];
            c[1] = str[j + 1];
            sscanf(c, "%02x" , &bytes[0]);
            UnChar[counter] = bytes[0];
            counter++;
        }
    }
    return;
}

int hexstringtobyte(char *in, unsigned char *out) {
    int len = (int)strlen(in);
    char *str = (char *)malloc(len);
    memset(str, 0, len);
    memcpy(str, in, len);
    for (int i = 0; i < len; i+=2) {
        //小写转大写
        if(str[i] >= 'a' && str[i] <= 'f') str[i] = str[i] & ~0x20;
        if(str[i+1] >= 'a' && str[i] <= 'f') str[i+1] = str[i+1] & ~0x20;
        //处理第前4位
        if(str[i] >= 'A' && str[i] <= 'F')
        out[i/2] = (str[i]-'A'+10)<<4;
        else
        out[i/2] = (str[i] & ~0x30)<<4;
        //处理后4位, 并组合起来
        if(str[i+1] >= 'A' && str[i+1] <= 'F')
        out[i/2] |= (str[i+1]-'A'+10);
        else
        out[i/2] |= (str[i+1] & ~0x30);
    }
    free(str);
    return 0;
}

void HexStrToByte(const char* source, unsigned char* dest, int sourceLen)
{
    short i;
    unsigned char highByte, lowByte;
    
    for (i = 0; i < sourceLen; i += 2)
    {
        highByte = toupper(source[i]);
        lowByte = toupper(source[i + 1]);
        
        if (highByte > 0x39)
            highByte -= 0x37;
        else
            highByte -= 0x30;
        
        if (lowByte > 0x39)
            lowByte -= 0x37;
        else
            lowByte -= 0x30;
        
        dest[i / 2] = (highByte << 4) | lowByte;
    }
    return ;
}



@end
