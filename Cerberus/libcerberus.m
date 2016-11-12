//
//  libcerberus.m
//  Cerberus
//
//  Created by haifisch on 11/11/16.
//  Copyright © 2016 haifisch. All rights reserved.
//

#import "libcerberus.h"

@implementation libcerberus

- (id)init {
    if (self = [super init]) {
        NSLog(@"libcerberus initiated...");
        return self;
    } else
        return nil;
}


- (NSData *)cerberus_user_public_key {
    if ([[NSUserDefaults standardUserDefaults] objectForKey:@"enclave_user_public_key"]) {
        return [[NSUserDefaults standardUserDefaults] objectForKey:@"enclave_user_public_key"];
    }
    NSLog(@"[libcerberus] No keys found in user defaults");
    return nil;
}

@end
