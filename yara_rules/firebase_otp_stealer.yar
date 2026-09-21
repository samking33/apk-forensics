rule Firebase_OTP_Stealer_Banking_Trojan
{
    meta:
        description = "Detects Firebase-based OTP forwarding banking trojan (AppointmentBookingTrojan family)"
        author      = "TGCSB Malware Analysis Team"
        date        = "2026-06-21"
        severity    = "CRITICAL"
        family      = "AppointmentBookingTrojan"
        reference   = "Firebase project syndi8-6d74a investigation"

    strings:
        // Firebase OTP C2 pattern
        $firebase_api  = "AIzaSy" ascii wide
        $firestore_url = "firestore.googleapis.com" ascii wide
        $admin_number  = "admin/number" ascii wide
        $devices_otps  = "devices/" ascii wide

        // OTP forwarding behaviour
        $sms_forward   = "sendTextMessage" ascii wide
        $sms_manager   = "android/telephony/SmsManager" ascii wide
        $otp_receiver  = "OtpReceiver" ascii wide
        $sms_forwarder = "SmsForwarder" ascii wide

        // C2 admin pattern
        $admin_num_mgr = "AdminNumberManager" ascii wide

        // Boot persistence
        $boot_recv     = "RECEIVE_BOOT_COMPLETED" ascii wide
        $boot_class    = "BootReceiver" ascii wide

    condition:
        $firebase_api and $firestore_url
        and ($admin_number or $devices_otps)
        and ($sms_forward or $sms_manager or $sms_forwarder or $otp_receiver or $admin_num_mgr)
        and ($boot_recv or $boot_class)
}

rule Firebase_OTP_Stealer_Lightweight
{
    meta:
        description = "Lightweight detection — Firebase + SMS forwarding (may miss some obfuscated variants)"
        severity    = "HIGH"
        family      = "FirebaseOTPStealer"

    strings:
        $firebase_api  = "AIzaSy" ascii wide
        $sms_send      = "sendTextMessage" ascii wide
        $recv_sms_perm = "RECEIVE_SMS" ascii wide
        $firestore     = "firestore" ascii wide nocase

    condition:
        $firebase_api and $sms_send and ($recv_sms_perm or $firestore)
}

rule APK_Dropper_Silent_Install
{
    meta:
        description = "APK dropper — silently installs payload APK"
        severity    = "HIGH"
        family      = "Dropper"

    strings:
        $req_install   = "REQUEST_INSTALL_PACKAGES" ascii wide
        $pkg_installer = "PackageInstaller" ascii wide
        $session_commit= "commitSession" ascii wide
        $recv_sms      = "RECEIVE_SMS" ascii wide
        $firebase_api  = "AIzaSy" ascii wide

    condition:
        $req_install and $pkg_installer and $session_commit
        and ($recv_sms or $firebase_api)
}
