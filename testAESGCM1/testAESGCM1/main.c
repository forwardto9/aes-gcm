#include "gcm.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>

#define CIPHERWRAPPER 0

static void single_encryption(void) {
    unsigned char buf[640] = {0};
    unsigned char decrpto[6400] = {0};
    unsigned char tag_buf[16];
    int ret;
    
    
    const unsigned char key[] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };
    
    const unsigned char initial_value[] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
    };
    
    const unsigned char additional[] = {};
    
    unsigned char plaintext[] = "helloworld xxx";
    const unsigned char tag[] = "c18ac253fbe6e8bb695e511070b552ce";
    unsigned char hexTag[16] = {0};
    
    hexstringtobyte(tag, hexTag);
    
    const unsigned char input[] = "e0904d84ba9601b2a74f0a481a10c236553db94c0d0e7f187aee2d7bd0ee603944cb2205804ad87a1172353da06f487488e5c4a8a57123a3e272ff8a67b2bbb6e49154a2f7cbd7c3d99f9b70ab15b35775bec5c6a2fe14071ae16e2df215c64dd27f2ccfe64a3286723625f47d554614a08ecdd75752b614b2ec93023e28f561caefcf8889029c2d154c57896a4251a9a3ddb9f2007faa18bef18cbd5852c35f261436738f93c9802d65fae4426b45dad5c50ba487f307055188dbf4f39c3269cad56bdca0ea8bc7c2a1ad83957c8c9e0cffd1471f1f912d69afac18b8bb8918dfee5ccbab77b4c285ee1457676f08fdd4e44db6e50cd42ae4c6596c4307884e520545e685fbc9c866b32eae34a1578df20d162e1865fe755ed991c1498fd8e7bc29aa10ea39aa680252a966b15a8c8de9645a9bd8e65c55b4d76396b2d86cdffa1b6eeb20c77c01153903fb38b6aab9e693148108d1954c1787db09ddfb3bd9bb9538c327dc3fa1c6f860f861ab35b1b7d02894c6d06a8b0184dfdb4d3c925a15587cc752276e4d7b59923c864df16571a5d832f9bf9c92c5d31a03c6a995ecdbbb5e72cdfa3e6a64124d51c922b11935baa871aba64ecc05a98ca10723c827206d612c13192af11aa1037bc0c26757274c7cca30cb85e9a78109e6ed5edd97c3151a5d92079efa3cbaedb13832b12f31df9baa2e6341462d674440dd2bdb092e9ef5ace93397ee652c2b7e3c67c04f883298ee51bd133c9a68cf551e063071fdd03251f251c73774ff26c6b030bb89d517ddd5d79282a882adb070272515fc848a0c115b450f42bd354f37daf77b6410ae13fa0a299293e559123ba4278f7861194980ea738057fe64524d99af00ffca31a8eb6310c1e127b9e9e3f9abfd50f778565d016f3c361b4891b74a91f0f1b1fe9e002bf8dbc3a0638f070073e4f14d05837aba5f7f40c44df9daf3ba06833f0c2b0564d794a9cf0e1a868ea0116d251f3c6b7ca44e2a1cf6fee7937cce27f4aab7c07750e741831c51b9b807faef40974af1d89007c378a38d0a86d7440c3f449db8d3b168bd538420e2e0d6ce9498dbdcde8a236e7af8fd5a3c057263c688fc4a8cf95f306e070b820c0dde4736d5ff1fe0c37ecec2af1d9dd1b44a19f3bf568ab499515dbb492d34904c37acfb884b09b880d64429041975e8a4009d6f48c3abc5a9d5e56cab983ce1c19dd39bf6871242470d14f1a210c56e1238d2588d65a21c28e7bac5e13e0df158d824f15db0a6c14d7d64043d0f7af267259ffa03cec5101cac9012c584082d0b21b410748cc9be464a45ea6de5250e09905d812ccd61af6391511588ec7f4cbee84ead526c518dc084cbea839e7cba90f0501dafce8187c2f1c20e83";
    unsigned char hexInput[6400] = {0};
    
    hexstringtobyte(input, hexInput);
    
#if CIPHERWRAPPER
    
    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);
    mbedtls_cipher_setup(&ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM));
    mbedtls_cipher_setkey(&ctx, key, 128, MBEDTLS_ENCRYPT);
    
    size_t o = 0;

    ret = mbedtls_cipher_auth_encrypt(&ctx, initial_value, 12, additional, 0, plaintext, sizeof(plaintext), buf, &o, tag_buf, 16);
    
    mbedtls_cipher_free(&ctx);
    
    
    mbedtls_cipher_init(&ctx);
    mbedtls_cipher_setup(&ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM));
    mbedtls_cipher_setkey(&ctx, key, 128, MBEDTLS_DECRYPT);
    //    mbedtls_cipher_auth_decrypt(&ctx, initial_value, 12, additional, 0, buf, strlen(buf), decrpto, &o, tag_buf, 16); // 本地反向测试
    // 需要使用sizeof(input)，因为input实际是16进制串，每两位是一个16进制表示；
    // strlen 获取hexInput 长度的时候，会因为遇到 0而提前终止，故不能使用，而从input即可知道原始长度
    // 注意sizeof和strlen的使用区别
    ret = mbedtls_cipher_auth_decrypt(&ctx, initial_value, 12,
                                      additional, 0,
                                      hexInput, sizeof(input)/2,
                                      decrpto, &o,
                                      hexTag, 16); // 联调反向测试
    
    mbedtls_cipher_free(&ctx);
    
#else
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
    
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init( &ctx );
    
    ret = mbedtls_gcm_setkey( &ctx, cipher, key, 128);
    
    ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, sizeof(plaintext), initial_value, 12, additional, 0, plaintext, buf, 16, tag_buf);
    
    ret = mbedtls_gcm_crypt_and_tag( &ctx, MBEDTLS_GCM_DECRYPT,
                                    sizeof(input),
                                    initial_value, 12,
                                    additional, 0,
                                    hexInput, decrpto,
                                    16, hexTag);
    
    mbedtls_gcm_free( &ctx );
    
#endif
    
    
    printf("明文: length(%lu): \n", sizeof(plaintext));
    for (int  i = 0; i < sizeof(plaintext); i++) {
        printf("%.2x", plaintext[i]);
    }
    printf("\n");
    
    char out[1024] = {0};
    bytetohexstring(buf, strlen(buf), out);
    printf("密文 : length(%lu)\n", strlen(out));
    printf("%s\n", out);
    for (int  i = 0; i < strlen(out)/2; i++) {
        printf("%.2x", buf[i]);
    }
    printf("\n");
    
    printf("tag: \n");
    for (int  i = 0; i < sizeof(tag_buf); i++) {
        printf("%.2x", tag_buf[i]);
    }
    printf("\n");
    
    printf("code = %d\n 解密：%s\n", ret, decrpto);
}

int main(void) {
    //    mbedtls_gcm_self_test(1);
    single_encryption();
    return 0;
}
