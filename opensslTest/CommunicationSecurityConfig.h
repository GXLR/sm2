//
//  CommunicationSecurityConfig.h
//  Tiny
//
//  Created by 徐涛 on 2018/11/20.
//  Copyright © 2018 xiangfp. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface CommunicationSecurityConfig : NSObject

+(instancetype) shareInstance;
//@property(nonatomic,copy)void(^retryRequest)();

-(void)securityConfigWithRequest:(id)request;

//-(void)resetRequestConfigWidthBase:(NSString *)base path:(NSString *)path;
//解码
-(NSString *)decodeWithStr:(NSString *)codedStr;

//请求秘钥
-(void)resetEncryption;

-(void)DHInit;

@end

NS_ASSUME_NONNULL_END
