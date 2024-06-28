<?php
function checkDomainReputation($domain) {
    $apiKey = 'PUT_YOUR_BASE64_ENCODED_IMAGE_HERE'; // Ganti dengan API key Anda
    $url = "https://www.virustotal.com/api/v3/domains/$domain";

    $curl = curl_init();

    curl_setopt_array($curl, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => "",
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => "GET",
        CURLOPT_HTTPHEADER => [
            "x-apikey: $apiKey"
        ],
    ]);

    $response = curl_exec($curl);
    $err = curl_error($curl);

    curl_close($curl);

    if ($err) {
        return null;
    } else {
        return json_decode($response, true);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $emailHeader = $_POST['emailHeader'];
    $suspicious = false;

    // Ekstraksi domain dari header email
    preg_match_all('/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/', $emailHeader, $matches);
    $domains = array_unique($matches[1]);

    // Daftar domain yang sering digunakan dalam phishing
    $phishingDomains = [
        'mktomail.com',
        'go.metamail.com',
        'mail.ru',
        '163.com',
        'qq.com',
        'xyz.com',
        'abc.com',
        'example.com',
        'yopmail.com',
        'mailinator.com',
        'trashmail.com',
        '10minutemail.com',
        'tempmail.com',
        'guerrillamail.com',
        'cock.li',
        'protonmail.com',
        'outlook.com',
        'aol.com',
        'yahoo.com',
        'zoho.com',
        'tutanota.com',
        'rediffmail.com',
        'gmx.com',
        'web.de',
        '163.com',
        '126.com',
        '21cn.com',
        'sina.com',
        'sohu.com',
        'tom.com',
        'aliyun.com',
        '126.net',
        'asia.com',
        'yandex.ru',
        'mail.bg',
        'mail.be',
        'freemail.hu',
        'laposte.net',
        'orange.fr',
        'wanadoo.fr',
        'libero.it',
        'virgilio.it',
        'email.it',
        'tin.it',
        'tiscali.it',
        'tele2.it',
        'fastwebnet.it',
        'iol.it',
        'inwind.it',
        'alice.it',
        'nifty.com',
        'mail.kz',
        'seznam.cz',
        'centrum.cz',
        'volny.cz',
        'azet.sk',
        'zmail.ru',
        'bk.ru',
        'list.ru',
        'inbox.ru',
        'webmail.co.za',
        'netspace.net.au',
        'bigpond.com',
        'optusnet.com.au',
        'ozemail.com.au',
        'iinet.net.au',
        'tpg.com.au',
        'vodafone.com.au',
        'netscape.net',
        'lavabit.com',
        'hushmail.com',
        'mail.cc',
    ];

    // Memeriksa apakah header email mengandung salah satu domain mencurigakan
    foreach ($domains as $domain) {
        if (in_array($domain, $phishingDomains)) {
            $suspicious = true;
            break;
        }
    }

    // Jika tidak ditemukan domain mencurigakan, periksa dengan VirusTotal
    if (!$suspicious) {
        foreach ($domains as $domain) {
            $result = checkDomainReputation($domain);
            if ($result && isset($result['data']['attributes']['last_analysis_stats']['malicious']) &&
                $result['data']['attributes']['last_analysis_stats']['malicious'] > 0) {
                $suspicious = true;
                break;
            }
        }
    }

    echo json_encode(['suspicious' => $suspicious]);
    exit;
}
?>
