rule Banking_Trojan_Credential_Stealer
{
    meta:
        description = "Generic banking credential stealer — fake bank/support app with form data exfil"
        severity    = "HIGH"
        family      = "BankingTrojan"
        author      = "TGCSB Malware Analysis Team"
        date        = "2026-06-21"

    strings:
        // Fake legitimacy strings
        $fake_bank1   = "customer support" ascii wide nocase
        $fake_bank2   = "appointment booking" ascii wide nocase
        $fake_bank3   = "bank helpline" ascii wide nocase
        $fake_bank4   = "KYC update" ascii wide nocase

        // Credential field names
        $cred_upi     = "upi_pin" ascii wide nocase
        $cred_atm     = "atm_pin" ascii wide nocase
        $cred_cvv     = "cvv" ascii wide nocase
        $cred_card    = "card_number" ascii wide nocase
        $cred_netbank = "password" ascii wide

        // SMS stealing
        $sms_perm     = "RECEIVE_SMS" ascii wide
        $sms_read     = "READ_SMS" ascii wide

        // Firebase exfil
        $firebase     = "firestore.googleapis.com" ascii wide

    condition:
        ($fake_bank1 or $fake_bank2 or $fake_bank3 or $fake_bank4)
        and ($cred_upi or $cred_atm or $cred_cvv or $cred_card or $cred_netbank)
        and ($sms_perm or $sms_read)
        and $firebase
}

rule Suspicious_Permissions_Combo
{
    meta:
        description = "Suspicious permission combination — SMS + install + contacts (high risk)"
        severity    = "MEDIUM"

    strings:
        $recv_sms     = "RECEIVE_SMS" ascii wide
        $send_sms     = "SEND_SMS" ascii wide
        $req_install  = "REQUEST_INSTALL_PACKAGES" ascii wide
        $read_contacts= "READ_CONTACTS" ascii wide
        $read_call_log= "READ_CALL_LOG" ascii wide
        $device_admin = "BIND_DEVICE_ADMIN" ascii wide

    condition:
        $recv_sms and $send_sms and $req_install
        and ($read_contacts or $read_call_log or $device_admin)
}
