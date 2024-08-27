'use strict';
let webcrypto = require('webcrypto');
let crypto = require('crypto')
import cf from 'cloudfront';

async function decrypt(encryptedBase64, keyBase64, ivBase64) {
            // Convert base64 to Uint8Array
       
            const keyBuffer = Uint8Array.from(atob(keyBase64), c => c.charCodeAt(0));
            const ivBuffer = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
            const encryptedBuffer = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
    
            // Import the key
            const key = await webcrypto.subtle.importKey(
                'raw',
                keyBuffer,
                { name: 'AES-CBC' },
                false,
                ['decrypt']
            );

            // Decrypt the data
            const decryptedBuffer = await webcrypto.subtle.decrypt(
                { name: 'AES-CBC', iv: ivBuffer },
                key,
                encryptedBuffer
            );

            // Convert decrypted buffer to string
            const decoder = new TextDecoder();
            const decryptedText = decoder.decode(decryptedBuffer);
            console.log("Decrypted Text:", decryptedText);
            return decryptedText;
            
}

async function handler(event) {
    // Replace with your actual base64-encoded values
        const encryptedBase64 = "gDMQf9BGlcCowwz2jslhJQ==";
        const keyBase64 = "TUpEbUp0Y3hBREExemJaNnhPRmQ0U2gwdzIyOHU3QWY=";
        const ivBase64 = "MDEyMzQ1Njc4OWFiY2RlZg==";

        let result = await decrypt(encryptedBase64, keyBase64, ivBase64);
        event.request.headers['result'] = {value:result}
        return event.request;
    
}