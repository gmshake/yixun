#import "yiXunGUI.h"

#include <arpa/inet.h>
#include "common_logs.h"
#include "radius.h"
#include "login_state.h"

#include "common_macro.h"

//#include "listen_thread.h"

BOOL settingChanged = NO;
NSTimer *keepalive_timer = nil;
NSThread *mlistenThread = nil;

struct yixun_msg msg;

@implementation yiXunGUI
- (IBAction)aExit:(id)sender {
    [self terminalExternalProcess];
	if (log_out(&msg) < 0) {
		dprint_info();
	}
    
    if (mlistenThread != nil) {
        [mlistenThread cancel];
        [mlistenThread release];
        mlistenThread = nil;
    }
    

    [self changeUIState];
	dprint_info();
    if (keepalive_timer != nil) {
        [keepalive_timer invalidate];
        keepalive_timer = nil;
    }
}

- (IBAction)aLogin:(id)sender {
    [self settingSave];
	[self changeUIState];
    
    msg.username = [[mUsername stringValue] UTF8String];
    msg.password = [[mPassword stringValue] UTF8String];
    msg.serverip = [[mServerIP stringValue] UTF8String];
    msg.clientip = [[mClientIP stringValue] UTF8String];
    msg.mac = [[mMAC stringValue] UTF8String];
    
    int retry_count = 2;
    do
    {
        int rval = log_in(&msg);
        [self changeUIState];
        dprint_info();
        
        if (rval == 0)
        {
            if (mlistenThread == nil)
                mlistenThread = [[ NSThread alloc] initWithTarget:self 
                                                       selector:@selector(listenThread:) 
                                                         object:nil];
            [mlistenThread start];
            
            keepalive_timer = [NSTimer scheduledTimerWithTimeInterval: msg.timeout
                                                     target: self
                                                   selector: @selector(keepalive:)
                                                   userInfo: nil
                                                    repeats: YES];
            [self runExternalProcess];
            if ([mAutoHide intValue]) [mApp hide:self];
            return;
        }
        else if (rval > 0)
            break;
        sleep(1);
    }while ([mAutoReconnect intValue] && --retry_count > 0);
}

- (void)changeUIState
{
    enum login_state s = get_login_state();
    switch (s) {
        case not_login:
            [mLogin setTitle:@"Login"];
            [mLogin setEnabled:YES];
            [mExit setEnabled:NO];
            
            [mUsername setEnabled:YES];
            [mPassword setEnabled:YES];
            [mServerIP setEnabled:YES];
            [mClientIP setEnabled:YES];
            [mMAC setEnabled:YES];
            break;
        case connecting:
            [mLogin setTitle:@"Conneting..."];
            [mLogin setEnabled:NO];
            [mExit setEnabled:NO];
            
            [mUsername setEnabled:NO];
            [mPassword setEnabled:NO];
            [mServerIP setEnabled:NO];
            [mClientIP setEnabled:NO];
            [mMAC setEnabled:NO];
            break;
        case connected:
            [mLogin setTitle:@"Conneted"];
            [mLogin setEnabled:NO];
            [mExit setEnabled:YES];
            
            [mUsername setEnabled:NO];
            [mPassword setEnabled:NO];
            [mServerIP setEnabled:NO];
            [mClientIP setEnabled:NO];
            [mMAC setEnabled:NO];
            break;
        default:
            DNSLog(@"Unkown state %d", s);
            break;
    }
 }

- (IBAction)hideShow:sender
{
    if ([mMainWindow isVisible])
        [mMainWindow orderOut:self];
    else
        [mMainWindow orderFront:self];
}    

- (void)settingRestore {
	DNSLog(@"Restore settings");
	
	NSUserDefaults *defaults=[NSUserDefaults standardUserDefaults];
	NSString* str;
	str = [defaults stringForKey:@"Username"];
	if (str != nil) [mUsername setStringValue:str];
	str = [defaults stringForKey:@"Password"];
	if (str != nil) [mPassword setStringValue:str];
    str = [defaults stringForKey:@"ServerIP"];
    if (str != nil) [mServerIP setStringValue:str];
    str = [defaults stringForKey:@"ClientIP"];
    if (str != nil) [mClientIP setStringValue:str];
    str = [defaults stringForKey:@"MAC"];
    if (str != nil) [mMAC setStringValue:str];

	[mAutoConnect setIntValue:[defaults integerForKey:@"AutoLogin"]];
    [mAutoReconnect setIntValue:[defaults integerForKey:@"AutoReLogin"]];
    [mAutoHide setIntValue:[defaults integerForKey:@"AutoHide"]];
}

- (void)settingSave {
	if (!settingChanged) return;
	DNSLog(@"Save settings");
	
	NSUserDefaults *defaults=[NSUserDefaults standardUserDefaults];
	[defaults setObject:[mUsername stringValue] forKey:@"Username"];
	[defaults setObject:[mPassword stringValue] forKey:@"Password"];
    [defaults setObject:[mServerIP stringValue] forKey:@"ServerIP"];
    [defaults setObject:[mClientIP stringValue] forKey:@"ClientIP"];
    [defaults setObject:[mMAC stringValue] forKey:@"MAC"];
	[defaults setInteger:[mAutoConnect intValue] forKey:@"AutoLogin"];
    [defaults setInteger:[mAutoReconnect intValue] forKey:@"AutoReLogin"];
    [defaults setInteger:[mAutoHide intValue] forKey:@"AutoHide"];
	settingChanged = NO;
}

- (void)awakeFromNib {   
	[self settingRestore];
	if ([mAutoConnect intValue])
        [self aLogin:NULL]; //自动连接
}

- (void)applicationWillTerminate:(NSNotification *)aNotification {
	if ([mExit isEnabled])
    {
        [self aExit:NULL];
        //sleep(1); // wait log out
    }
    [self settingSave];
}

- (BOOL)windowShouldClose:(id)sender
{
    enum login_state s = get_login_state();
    if (s == connected)
        [mApp hide:self];
    else
    {
        /*
        NSAlert *alert = [[NSAlert alloc] init]; 
        [alert setMessageText:@"Are you really want to QUIT?"]; 
        //[alert setInformativeText:@"Informative text"]; 
        //[alert setAlertStyle:NSWarningAlertStyle];
        [alert addButtonWithTitle:@"Yes"];
        [alert addButtonWithTitle:@"No"];
        
         
        NSInteger result = [alert runModal]; 
        [alert  release];
        */
        //NSInteger result;
        
        NSString *title = @"Notice";
        NSString *defaultButton = @"Yes";
        NSString *alternateButton = @"No";
        NSString *otherButton = nil;
        NSString *message = @"Are you sure you want to QUIT?";
        
        NSBeginAlertSheet(title, defaultButton, alternateButton, otherButton, mMainWindow, self, @selector(sheetDidEnd:returnCode:contextInfo:), nil, nil, message); 
         /*
        if (result == NSAlertFirstButtonReturn)
        {
            [mApp terminate:self];
            return YES;
        }
          */
    }
    return NO;
}

- (void)sheetDidEnd:(NSWindow *)sheet returnCode:(int)returnCode contextInfo:(void *)contextInfo 
{
    if ( returnCode == NSAlertDefaultReturn )
    { 
        DNSLog(@"Default Return");
        [mApp terminate:self];
    } 
    else
        DNSLog(@"Other Return");
} 

- (IBAction)aSettingChanged:(id)sender {
    settingChanged = YES;
}

- (void)runExternalProcess
{
	NSTask *task = [[NSTask alloc] init];
	NSPipe *pipe = [NSPipe pipe];
#ifdef DEBUG
	NSFileHandle *readHandle = [pipe fileHandleForReading];
	NSData *inData = nil;
#endif
    NSMutableArray *arguments=[[NSMutableArray alloc] init];

    [arguments addObject:@"-D"];
    [arguments addObject:[NSString stringWithFormat:@"%s %s", "-l", inet_itoa(msg.gre_local)]];
    [arguments addObject:[NSString stringWithFormat:@"%s %s", "-r", inet_itoa(msg.gre_remote)]];
    [arguments addObject:[NSString stringWithFormat:@"%s %s", "-s", inet_itoa(msg.gre_src)]];
    [arguments addObject:[NSString stringWithFormat:@"%s %s", "-d", inet_itoa(msg.gre_dst)]];
    [arguments addObject:[NSString stringWithFormat:@"%s %s", "-n", inet_itoa(msg.gre_netmask)]];
    
	[task setStandardOutput:pipe];
	[task setLaunchPath:@"/usr/local/bin/gre-config"];
	[task setArguments:arguments];
	[task launch];

#ifdef DEBUG
	while((inData = [readHandle availableData]) && [inData length])
	{
		NSString *temp = [[NSString alloc] initWithData:inData encoding:NSUTF8StringEncoding];
        NSLog(temp);
	}
#endif
	[task release];
    [arguments release];
}

- (void)terminalExternalProcess
{
	NSTask *task = [[NSTask alloc] init];
	NSPipe *pipe = [NSPipe pipe];
#ifdef DEBUG
	NSFileHandle *readHandle = [pipe fileHandleForReading];
	NSData *inData = nil;
#endif
    NSMutableArray *arguments=[[NSMutableArray alloc] init];
    
    [arguments addObject:@"-q"];
    
	[task setStandardOutput:pipe];
	[task setLaunchPath:@"/usr/local/bin/mac-gre"];
	[task setArguments:arguments];
	[task launch];
#ifdef DEBUG    
	while((inData = [readHandle availableData]) && [inData length])
	{
		NSString *temp = [[NSString alloc] initWithData:inData encoding:NSUTF8StringEncoding];
        NSLog(temp);
	}
#endif    
	[task release];
    [arguments release];
}

- (void)listenThread: (id)arg
{
    while(1) {
        accept_client(&msg);
    }
}

- (void)keepalive: (NSTimer *) timer
{
    DNSLog(@"Send keep-alive packet");
    if (keep_alive(&msg) < 0) // error when sending keep-alive package
    {
        sleep(1);
        if (keep_alive(&msg) < 0)
        {
            [self aExit:NULL];
            if ([mAutoReconnect intValue])
                [self aLogin:NULL]; //自动重新连接
        }
    }
    
}

@end
