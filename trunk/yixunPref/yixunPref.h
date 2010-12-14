//
//  yixunPref.h
//  yixun
//
//  Created by Summer Town on 10/6/10.
//  Copyright (c) 2010 __MyCompanyName__. All rights reserved.
//

#import <PreferencePanes/PreferencePanes.h>
/*
enum ui_status
{
    notconnect,
    connecting,
    connected,
};
*/

@interface yixunPref : NSPreferencePane 
{
    IBOutlet NSButton *m_connect;
    IBOutlet NSTextField *m_user;
    IBOutlet NSTextField *m_pwd;
    IBOutlet NSButton *m_autoconnect;
    IBOutlet NSButton *m_autoreconnect;
    IBOutlet NSButton *m_autodisconnect;
    IBOutlet NSProgressIndicator *m_status;
}

- (IBAction)aAction:(id)sender;
- (IBAction)aSettingChanged:(id)sender;
- (void)mainViewDidLoad;
- (void)settingsRestore;
- (void)settingsSave;
- (BOOL)progisRunning;
- (void)changeUIState;
- (void)timerCallback:(NSTimer *)timer;
@end
