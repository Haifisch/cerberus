//
//  libenclave.h
//  libenclave
//
//  Created by haifisch on 11/9/16.
//  Copyright © 2016 haifisch. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Ed25519.h"

@interface libenclave : NSObject

- (void)enclave_delete_message:(int)message_id;
- (void)enclave_submit_nonce;
- (NSData *)enclave_server_public_key;
- (BOOL)is_enclave_user_public_key_stored:(NSString *)public_key;
- (BOOL)enclave_user_submit_public_key:(NSString *)public_key withKeypair:(ECKeyPair *)keypair;
- (NSArray *)enclave_user_queue:(NSString *)public_key;
- (NSData *)enclave_user_pub:(NSString *)public_key forRecieverID:(NSString *)reciever_id;
@end
