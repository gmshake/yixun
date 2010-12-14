//
//  yixunPref.m
//  yixun
//
//  Created by Summer Town on 10/6/10.
//  Copyright (c) 2010 __MyCompanyName__. All rights reserved.
//

#import "yixunPref.h"
#include <string.h>
#include <errno.h>

#define LOCKFILE "/var/tmp/yixun.pid"        /* 锁文件 */

static NSTimer *check_timer = nil;
static BOOL yixunIsRunning = NO;
static BOOL settingChanged = NO;
//const static CFStringRef appID = CFSTR("com.SummerTown.yixun");


@implementation yixunPref

- (void) mainViewDidLoad
{
    [m_status setDisplayedWhenStopped:NO];
    //[m_user setStringValue:@"S1.155.85@qzu"];
    //[m_pwd setStringValue:@"S1.155.85@qzu"];
    [self settingsRestore];
    if (check_timer != nil) {
        [check_timer invalidate];
        check_timer = nil;
    }

    check_timer = [NSTimer scheduledTimerWithTimeInterval: 1
                                                   target: self
                                                 selector: @selector(timerCallback:)
                                                 userInfo: nil
                                                  repeats: YES];

    [check_timer fire];
    if ([m_autoconnect intValue] && !yixunIsRunning)
        [self aAction:NULL];

}

- (void)didUnselect
{
    NSLog(@"didUnselect");
    if (check_timer != nil) {
        [check_timer invalidate];
        check_timer = nil;
    }
    [self settingsSave];
}

/*
- (void)restoreSettings
{
    CFStringRef key = CFSTR("PrefKey");
    CFPropertyListRef value; // Any allowed data type
    
    value = CFPreferencesCopyAppValue(key, appID);
    CFPreferencesSetAppValue(key, value, appID);
}
*/
- (IBAction)aSettingChanged:(id)sender
{
    settingChanged = YES;
}

- (void)settingsRestore {
	NSLog(@"Restore settings");
	
	NSUserDefaults *defaults=[NSUserDefaults standardUserDefaults];
	NSString* str;
	str = [defaults stringForKey:@"Username"];
	if (str != nil) [m_user setStringValue:str];
	str = [defaults stringForKey:@"Password"];
	if (str != nil) [m_pwd setStringValue:str];
    
    [m_autoconnect setIntValue:[defaults boolForKey:@"AutoConnect"]];
    [m_autoreconnect setIntValue:[defaults boolForKey:@"AutoReconnect"]];
    [m_autodisconnect setIntValue:[defaults boolForKey:@"AutoDisconnect"]];
	//[m_autoconnect setIntValue:[defaults integerForKey:@"AutoConnect"]];
    //[m_autoreconnect setIntValue:[defaults integerForKey:@"AutoReconnect"]];
    //[m_autodisconnect setIntValue:[defaults integerForKey:@"AutoDisconnect"]];
}

- (void)settingsSave {
	if (!settingChanged) return;
	NSLog(@"Save settings");
	
	NSUserDefaults *defaults=[NSUserDefaults standardUserDefaults];
    if (defaults == nil) NSLog(@"default == nil");
	[defaults setObject:[m_user stringValue] forKey:@"Username"];
	[defaults setObject:[m_pwd stringValue] forKey:@"Password"];
    [defaults setBool:[m_autoconnect intValue] forKey:@"AutoConnect"];
    [defaults setBool:[m_autoreconnect intValue] forKey:@"AutoReconnect"];
    [defaults setBool:[m_autodisconnect intValue] forKey:@"AutoDisconnect"];
	//[defaults setInteger:[m_autoconnect intValue] forKey:@"AutoConnect"];
    //[defaults setInteger:[m_autoreconnect intValue] forKey:@"AutoReconnect"];
    //[defaults setInteger:[m_autodisconnect intValue] forKey:@"AutoDisconnect"];
	settingChanged = NO;
}

- (IBAction)aAction:(id)sender
{
    /*
    NSTask *task = [[NSTask alloc] init];
    NSMutableString *suser = [[NSMutableString alloc] init];
    NSMutableString *spwd = [[NSMutableString alloc] init];
    //NSPipe *pipe = [NSPipe pipe];
    NSMutableArray *arguments=[[NSMutableArray alloc] init];
    if (yixunIsRunning) // Disconnect
    {
        [arguments addObject:@"-q"];
    }
    else
    {
        [suser appendString:@"-u"];
        [suser appendString:[m_user stringValue]];
        NSLog(suser);
        NSLog(spwd);
        [spwd appendString:@"-p"];
        [spwd appendString:[m_pwd stringValue]];
        
        [arguments addObject:@"-D"];
        [arguments addObject:suser];
        [arguments addObject:spwd];
        //[task setStandardOutput:pipe];
    }
    
    [task setLaunchPath:@"/usr/local/bin/yixun"];
    [task setArguments:arguments];
    [task launch];
    
    [task release];
    [arguments release];
    [suser release];
    [spwd release];
     */

    [m_status startAnimation:NULL];
    if (yixunIsRunning) {
        system("/usr/local/bin/yixun -q");
    } else {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "/usr/local/bin/yixun -D -u%s -p%s",
                 [[m_user stringValue] cStringUsingEncoding:NSUTF8StringEncoding],
                 [[m_pwd stringValue] cStringUsingEncoding:NSUTF8StringEncoding]);
        system(cmd);
    }
}

- (BOOL) progisRunning
{
    int fd = open(LOCKFILE, O_RDONLY);
    if (fd < 0) {
        NSLog(@"[progisRunning] Error open %s:%s", LOCKFILE, strerror(errno));
        return NO;
    }
    
    BOOL rval = NO;
    
    //Daemon running
    if (lockf(fd, F_TEST, 0) < 0) {
        rval = YES;
        close(fd);
    }
    
    //NSLog(rval ? @"yixun is running" : @"yixun is NOT running");

    return rval;
}
        
- (void) changeUIState
{
    static BOOL last_status = NO;
    if (yixunIsRunning == last_status) return;
    last_status = yixunIsRunning;
    switch (yixunIsRunning) {
        case NO:
            [m_connect setTitle:@"Connect"];
            [m_user setEnabled:YES];
            [m_pwd setEnabled:YES];
            break;
        default:
            [m_connect setTitle:@"Disconnect"];
            [m_user setEnabled:NO];
            [m_pwd setEnabled:NO];
            break;
    }
    [m_status stopAnimation:NULL];
    NSLog(@"New ui_state:%d", yixunIsRunning);
}

- (void)timerCallback:(NSTimer *)timer
{
    yixunIsRunning = [self progisRunning];
    [self changeUIState];
}

@end
