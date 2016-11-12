//
//  libcerberus.m
//  Cerberus
//
//  Created by haifisch on 11/11/16.
//  Copyright © 2016 haifisch. All rights reserved.
//

#import "libcerberus.h"
#import "Common.h"
#import "Randomness.h"
#import "NSData+CommonCrypto.h"

@implementation libcerberus {
    NSFileManager *privateFileManager;
}

- (id)init {
    if (self = [super init]) {
        privateFileManager = [[NSFileManager alloc] init];
        NSLog(@"libcerberus initiated...");
        return self;
    } else
        return nil;
}

- (char *)cerberus_request_keychain_unlock {
    char *passkey, *verification;
    passkey = getpass("Please enter a password to unlock your Cerberus keychain:\n");
    verification = getpass("Please verify the password again:\n");
    return passkey;
}

- (BOOL)cerberus_check_for_config {
    if ([privateFileManager fileExistsAtPath:DEFAULT_CONFIG_PATH isDirectory:nil]) {
        return YES;
    }
    return NO; // no file
}

- (void)cerberus_setup_config {
    printf("Cerberus creating path at %s\n", [DEFAULT_CERBERUS_PATH UTF8String]);
    BOOL fileIsDirectory;
    if (![privateFileManager fileExistsAtPath:DEFAULT_CERBERUS_PATH isDirectory:&fileIsDirectory]) {
        NSError *error;
        [privateFileManager createDirectoryAtPath:DEFAULT_CERBERUS_PATH withIntermediateDirectories:NO attributes:nil error:&error];
        if (error) {
            printf("Error creating Cerberus config path at %s\nCritical error, exiting...\n", [DEFAULT_CERBERUS_PATH UTF8String]);
            printf("%s", [error.localizedDescription UTF8String]);
            exit(0);
        }
    }
    printf("Generating Curve25519 keypair...\n");
    
    ECKeyPair *nkey = [Curve25519 generateKeyPair];
    printf("Public key; %s\n", [[nkey.publicKey base64EncodedStringWithOptions:0] UTF8String]);
    if (nkey.publicKey.length != 32) {
        printf("Public key length is not 32 bytes, something must be wrong with generation...\nCritical error, exiting...\n");
        exit(0);
    }
    NSData *keypairArchive = [NSKeyedArchiver archivedDataWithRootObject:nkey];
    NSDictionary *config_dict = [[NSDictionary alloc] initWithObjectsAndKeys:[keypairArchive base64EncodedStringWithOptions:0], @"keypair", [nkey.publicKey base64EncodedStringWithOptions:0],@"publickey", nil];
    
    NSData *json_encoded_config = [NSJSONSerialization dataWithJSONObject:config_dict options:0 error:nil];
    if (!json_encoded_config) {
        printf("JSON encoded config could not be created...\nCritical error, exiting...\n");
        exit(0);
    }
    
    
    NSMutableData *iv = [[Randomness  generateRandomBytes:32] mutableCopy];
    NSData *ivCopy = [iv copy];
    char *passkey = [self cerberus_request_keychain_unlock];
    
    NSMutableData *passkeyMunched = [[NSMutableData alloc] init];
    [passkeyMunched appendData:[NSData dataWithBytes:(__bridge const void * _Nullable)([NSString stringWithUTF8String:passkey]) length:sizeof(&passkey)]];
    [passkeyMunched appendData:iv];
    NSData *hashKeyData = [passkeyMunched SHA512Hash];
    NSString *hashedKey = [[NSString alloc] initWithData:hashKeyData encoding:NSASCIIStringEncoding];
    
    NSMutableData *encrypted_config = [[[AESCrypt encrypt:[NSString stringWithUTF8String:[json_encoded_config bytes]] password:hashedKey] dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    
    [encrypted_config replaceBytesInRange:NSMakeRange(0, 0) withBytes:ivCopy.bytes length:ivCopy.length];
    
    if (![privateFileManager createFileAtPath:DEFAULT_CONFIG_PATH contents:encrypted_config attributes:nil]) {
        printf("File could not be created.\nCritical error, exiting...\n");
        exit(0);
    }
    printf("Config file stored.\n");
    
}

- (NSData *)cerberus_user_public_key {
    NSMutableData *data = [[[NSFileManager defaultManager] contentsAtPath:DEFAULT_CONFIG_PATH] mutableCopy];
    NSRange range = NSMakeRange(0, 32);
    NSData *iv = [data subdataWithRange:range];
    [data replaceBytesInRange:NSMakeRange(0, 32) withBytes:NULL length:0];

    if (!data) {
        printf("Data from config path is empty.\nExiting...\n");
        exit(0);
    }
    
    NSString *encryptedJSON = [NSString stringWithUTF8String:[data bytes]];
    char *passkey = [self cerberus_request_keychain_unlock];
    
    NSMutableData *passkeyMunched = [[NSMutableData alloc] init];
    [passkeyMunched appendData:[NSData dataWithBytes:(__bridge const void * _Nullable)([NSString stringWithUTF8String:passkey]) length:sizeof(&passkey)]];
    [passkeyMunched appendData:iv];
    NSData *hashKeyData = [passkeyMunched SHA512Hash];
    NSString *hashedKey = [[NSString alloc] initWithData:hashKeyData encoding:NSASCIIStringEncoding];

    
    NSString *config_decrypted = [AESCrypt decrypt:encryptedJSON password:hashedKey];
    if (!config_decrypted) {
        printf("Config could not be decrypted! Check your password and try again.\nExiting...\n");
        exit(0);
    }
    NSError *error;
    NSDictionary *config_dict = [NSJSONSerialization JSONObjectWithData:[config_decrypted dataUsingEncoding:NSUTF8StringEncoding] options:0 error:&error];
    if (error) {
        printf("Config dictionary may be malformed, serialization has failed.\nExiting...\n");
        exit(0);
    }
    NSData *publickey = [[NSData alloc] initWithBase64EncodedData:config_dict[@"publickey"] options:0];
    if (publickey.length != 32) {
        printf("Config dictionary may be malformed, public key is not 32 bytes\nExiting...\n");
        exit(0);
    }
    return publickey;
}

@end
