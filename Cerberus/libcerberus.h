//
//  libcerberus.h
//  Cerberus
//
//  Created by haifisch on 11/11/16.
//  Copyright © 2016 haifisch. All rights reserved.
//

// libcerberus handles OS X side credential and config management 

#import <Foundation/Foundation.h>
#import "Curve25519.h"

@interface libcerberus : NSObject

@property (nonatomic) char *passkeyStore;
@property (nonatomic) BOOL hasSuccessfulLogin;

// Config management
- (BOOL)cerberus_check_for_config;
- (void)cerberus_setup_config;

// Keypair management
- (ECKeyPair *)cerberus_user_keypair;
- (NSData *)cerberus_user_public_key;

// Library misc
+ (instancetype)sharedInstance;

@end
