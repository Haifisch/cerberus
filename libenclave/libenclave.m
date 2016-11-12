//
//  libenclave.m
//  libenclave
//
//  Created by haifisch on 11/9/16.
//  Copyright © 2016 haifisch. All rights reserved.
//

#import "libenclave.h"
#define ENDPOINT_URL @"https://env1.suntzusecurity.com/enclave.php"

@implementation libenclave

- (id)init {
    if (self = [super init]) {
        NSLog(@"libenclave initiated...");
        return self;
    } else
        return nil;
}

- (void)enclave_delete_message:(int)message_id {
    
}

- (void)enclave_submit_nonce {
    
}

- (NSURL *)enclave_endpoint_url:(int)opcode {
    NSURL *endpoint;
    switch (opcode) {
        case 0: // request server public key
            endpoint = [NSURL URLWithString:[NSString stringWithFormat:@"%@?action=server_pub", ENDPOINT_URL]];
            break;
        
        case 1:
            endpoint = [NSURL URLWithString:[NSString stringWithFormat:@"%@?action=check_key", ENDPOINT_URL]];
            break;
        
        default:
            return nil;
            break;
    }
    return endpoint;
}

- (NSDictionary *)enclave_request_repsonse:(NSURL *)enclave_url {
    NSData *urlData = [NSData dataWithContentsOfURL:enclave_url];
    if (!urlData) {
        NSLog(@"[libenclave] urlData is null, cannot continue. Returning nil.");
        return nil;
    }
    NSError *error;
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:urlData options:0 error:&error];
    if (error || json == nil) {
        NSLog(@"[libenclave] json could not be parsed.");
        return nil;
    }
    return json;
}

- (NSData *)enclave_server_public_key {
    NSDictionary *public_key_reponse = [self enclave_request_repsonse:[self enclave_endpoint_url:0]];
    NSString *public_key_encoded = (NSString*)public_key_reponse[@"result"];
    NSData *public_key_data = [[NSData alloc] initWithBase64EncodedString:public_key_encoded options:0];
    if (sizeof(public_key_data) != 32) {
        NSLog(@"[libenclave] size of returned public key is no 32 bytes! something must be wrong... exiting.");
        return nil;
    }
    return public_key_data;
}

- (BOOL)is_enclave_user_public_key_stored:(NSData *)public_key {
    NSDictionary *server_check_reponse = [self enclave_request_repsonse:[self enclave_endpoint_url:1]];
    if (!(BOOL)server_check_reponse[@"error"]) {
        return NO;
    }
    return YES;
}


@end
