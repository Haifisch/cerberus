//
//  libcerberus.m
//  Cerberus
//
//  Created by haifisch on 11/11/16.
//  Copyright © 2016 haifisch. All rights reserved.
//

#import "libcerberus.h"
#import "Common.h"
#import "NSData+CommonCrypto.h"
#import "Randomness.h"

static id shared = NULL;

@implementation libcerberus {
    NSFileManager *privateFileManager;
}
@synthesize passkeyStore, hasSuccessfulLogin;

+ (instancetype)sharedInstance
{
    static libcerberus *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[libcerberus alloc] init];
        // Do any other initialisation stuff here
    });
    return sharedInstance;
}

- (id)init {
    if (self = [super init]) {
        privateFileManager = [[NSFileManager alloc] init];
        hasSuccessfulLogin = NO;
        passkeyStore = NULL;
        NSLog(@"libcerberus initiated...");
        return self;
    } else {
        return nil;
    }
}

- (void)setHasSuccessfulLogin:(BOOL)isGood {
    hasSuccessfulLogin = isGood;
}

- (void)setStoredPasskey:(char *)passkeyVar {
    passkeyStore = passkeyVar;
}

- (char *)cerberus_request_keychain_unlock {
    char *passkey = NULL, *verification;
    BOOL shouldReturn = NO;
    
    if ([[libcerberus sharedInstance] hasSuccessfulLogin]) {
        char *passkey = [[libcerberus sharedInstance] passkeyStore];
        if (strnlen(passkey, sizeof(passkey)) > 0) {
            return passkey;
        }
    } else {
        while (shouldReturn == NO) {
            passkey = getpass("Please enter a password to unlock your Cerberus keychain:\n");
            verification = getpass("Please verify the password again:\n");
            shouldReturn = YES;
            if (strlen(passkey) < 7) {
                shouldReturn = NO;
                printf("Keychain password must be at least 7 characters long! Try again.");
            }
        }
        if (strcmp(passkey, verification) == 0) {
            [[libcerberus sharedInstance] setHasSuccessfulLogin:YES];
            [[libcerberus sharedInstance] setStoredPasskey:passkey];
            return passkey;
        }
        printf("Passwords did not match!");
        return NULL;
    }
    return NULL;
}

- (BOOL)cerberus_check_for_config {
    if ([privateFileManager fileExistsAtPath:DEFAULT_CONFIG_PATH isDirectory:nil]) {
        return YES;
    }
    return NO; // no file
}

- (void)cerberus_setup_config {
    printf("Cerberus creating path at %s\n", [DEFAULT_CERBERUS_PATH UTF8String]);
    
    // check if cerberus config path exists already, if not create it, if so, skip opertion.
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
    // generate new 25519 keypair and check public key length
    printf("Generating Curve25519 keypair...\n");
    ECKeyPair *nkey = [Curve25519 generateKeyPair];
    printf("Public key; %s\n", [[nkey.publicKey base64EncodedStringWithOptions:0] UTF8String]);
    if (nkey.publicKey.length != 32) {
        printf("Public key length is not 32 bytes, something must be wrong with generation...\nCritical error, exiting...\n");
        exit(0);
    }
    
    // archive nkey data
    NSData *keypairArchive = [NSKeyedArchiver archivedDataWithRootObject:nkey];
    
    // setup config structure and fill values
    NSDictionary *config_dict = [[NSDictionary alloc] initWithObjectsAndKeys:[keypairArchive base64EncodedStringWithOptions:0], @"keypair", [nkey.publicKey base64EncodedStringWithOptions:0],@"publickey", nil];
    
    // encode dictionary into json data
    NSData *json_encoded_config = [NSJSONSerialization dataWithJSONObject:config_dict options:0 error:nil];
    if (!json_encoded_config) {
        printf("JSON encoded config could not be created...\nCritical error, exiting...\n");
        exit(0);
    }
    
    // generate new 32 byte long IV and make a copy for later
    NSMutableData *iv = [[Randomness  generateRandomBytes:32] mutableCopy];
    NSData *ivCopy = [iv copy];
    
    // request new passkey for encrypting the config file
    printf("When requested please input a new password to secure your Cerberus keychain with.\n");
    char *passkey = [self cerberus_request_keychain_unlock];
    if (!passkey) {
        printf("Passkey request returned empty.\nCritical error, exiting...\n");
        exit(0);
    }
    
    // setup passkey data
    NSMutableData *passkeyMunched = [[NSMutableData alloc] init];
    
    // append passkey
    [passkeyMunched appendData:[NSData dataWithBytes:(__bridge const void * _Nullable)([NSString stringWithUTF8String:passkey]) length:sizeof(&passkey)]];
    
    // append id
    [passkeyMunched appendData:iv];
    
    // sha512 the salted key
    NSData *hashKeyData = [passkeyMunched SHA512Hash];
    
    // NSData -> NSString
    NSString *hashedKey = [[NSString alloc] initWithData:hashKeyData encoding:NSASCIIStringEncoding];
    
    // encrypt config json
    NSMutableData *encrypted_config = [[[AESCrypt encrypt:[NSString stringWithUTF8String:[json_encoded_config bytes]] password:hashedKey] dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    
    // append the IV copy to the beginning of the config file
    [encrypted_config replaceBytesInRange:NSMakeRange(0, 0) withBytes:ivCopy.bytes length:ivCopy.length];
    
    // create and store encrypted config file
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


- (ECKeyPair *)cerberus_user_keypair {
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
    return [NSKeyedUnarchiver unarchiveObjectWithData:[[NSData alloc] initWithBase64EncodedData:config_dict[@"keypair"] options:0]];
}

@end
