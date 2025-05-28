/*
Copyright NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
const Certificate = pkijs.Certificate;



/**
 *	Convert base64 string to buffer
 *
 * @param {string} b64str
 */  
let base64StringToArrayBuffer = (b64str) => {
    let byteStr = atob(b64str);
    let bytes = new Uint8Array(byteStr.length);
    for (let i = 0; i < byteStr.length; i++) {
        bytes[i] = byteStr.charCodeAt(i);
    }
    return bytes.buffer;
}


/**
 *	Convert PEM string to binary
 *
 * @param {string} pem
 */  
let convertPemToBinary = (pem) => {
    var lines = pem.split('\n');
    var encoded = '';
    for(var i = 0;i < lines.length;i++){
        if (lines[i].trim().length > 0 &&
            lines[i].indexOf('-BEGIN RSA PRIVATE KEY-') < 0 && 
            lines[i].indexOf('-BEGIN RSA PUBLIC KEY-') < 0 &&
            lines[i].indexOf('-BEGIN PUBLIC KEY-') < 0 &&
            lines[i].indexOf('-BEGIN CERTIFICATE-') < 0 &&
            lines[i].indexOf('-BEGIN PRIVATE KEY-') < 0 &&
            lines[i].indexOf('-END PRIVATE KEY-') < 0 &&
            lines[i].indexOf('-END CERTIFICATE-') < 0 &&
            lines[i].indexOf('-END PUBLIC KEY-') < 0 &&
            lines[i].indexOf('-END RSA PRIVATE KEY-') < 0 &&
            lines[i].indexOf('-END RSA PUBLIC KEY-') < 0) {
            
            encoded += lines[i].trim();
        
        }
    }
    return base64StringToArrayBuffer(encoded);
}
  

/**
 *	Convert buffer to Certificate
 *
 * @param {Buffer} certificateBuffer
 */  
let convertBinaryToCertificate = (certificateBuffer) => {
    let asn1 = asn1js.fromBER(certificateBuffer);
    if(asn1.offset === (-1)) {
        console.log("Can not parse binary data");
    } 
    const certificate = new Certificate({ schema: asn1.result });
    return certificate;
}
 
// Function to parse a certificate
let parseCertificate = async function(pem) {
    const der = convertPemToBinary(pem);
    const asn1 = asn1js.fromBER(der);
    const cert = new Certificate({ schema: asn1.result });
    return cert;
}

// Function to split PEM chain into individual certificates
let splitPemChain = function(pemChain) {
    // Regular expression to match individual certificates
    const certRegex = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
    const matches = pemChain.match(certRegex);
    
    if (!matches) {
        throw new Error('No certificates found in the chain');
    }

    return matches;
}

let parseCertificateChain = async function(certChain) {
    const parsedCerts = [];
    
    let certificates = splitPemChain(certChain)

    for (const pem of certificates) {
        const cert = await parseCertificate(pem);
        parsedCerts.push(cert);
    }
    return parsedCerts;
}

/**
 *	Convert PEM to Certificate
 *
 * @param {string} pem
 */  
let convertPemToCertificate = async (pem) => {

    let parsedCerts = await parseCertificateChain(pem);

    return parsedCerts[0];

}

/**
 *	Convert buffer to Certificate
 *
 * @param {string} pem
 */  
let printCertificate = (certificate, logger) => {
    logger.debug('Certificate Issuance: ', certificate.notBefore.value.toString());
    logger.debug('Certificate Expiry: ', certificate.notAfter.value.toString());
}


/**
 *	Return time (in millis) for when Certificate expires
 *
 * @param {Buffer} certificateBuffer
 */  
let getExpiryTimeFromCertificate = (certificate) => {
    return certificate.notAfter.toSchema().toDate().getTime();
}


/**
 *	Return time (human-readable) for when Certificate expires
 *
 * @param {Buffer} certificateBuffer
 */  
let getExpiryStringFromCertificate = (certificate) => {
    return certificate.notAfter.toSchema().toDate().toString();
}


/**
 *	Return time (in millis) for when Certificate becomes usable
 *
 * @param {Buffer} certificateBuffer
 */  
let getBecomesUsableTimeFromCertificate = (certificate) => {
    return certificate.notBefore.toSchema().toDate().getTime();
}


/**
 *	Return time (human-readable) for when Certificate becomes usable
 *
 * @param {Buffer} certificateBuffer
 */  
let getBecomesUsableStringFromCertificate = (certificate) => {
    return certificate.notBefore.toSchema().toDate().toString();
}


export {
    base64StringToArrayBuffer,
    convertPemToBinary,
    convertBinaryToCertificate,
    convertPemToCertificate,
    splitPemChain,
    printCertificate,
    getExpiryTimeFromCertificate,
    getExpiryStringFromCertificate,
    getBecomesUsableTimeFromCertificate,
    getBecomesUsableStringFromCertificate
};