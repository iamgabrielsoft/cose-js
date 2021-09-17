/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cbor = require('cbor');
const EC = require('elliptic').ec;
const crypto = require('crypto');
const common = require('./common')
const Promise = require('any-promise');
const EMPTY_BUFFER = common.EMPTY_BUFFER
const Tagged = cbor.Tagged;

const SignTag = exports.SignTag = 98;
const Sign1Tag = exports.Sign1Tag = 18;


const AlgFromTags = {};
AlgFromTags[-7] = { 'sign': 'ES256', 'digest': 'SHA-256' };
AlgFromTags[-35] = { 'sign': 'ES384', 'digest': 'SHA-384' };
AlgFromTags[-36] = { 'sign': 'ES512', 'digest': 'SHA-512' };
AlgFromTags[-257] = { 'sign': 'RS256', 'digest': 'SHA-256' };
AlgFromTags[-258] = { 'sign': 'RS384', 'digest': 'SHA-384' };
AlgFromTags[-259] = { 'sign': 'RS512', 'digest': 'SHA-512' };

const COSEAlgToNodeAlg = {
  'ES256': { 'sign': 'p256', 'digest': 'sha256' },
  'ES384': { 'sign': 'p384', 'digest': 'sha384' },
  'ES512': { 'sign': 'p521', 'digest': 'sha512' },
  'RS256': { 'sign': 'RSA-SHA256' },
  'RS384': { 'sign': 'RSA-SHA384' },
  'RS512': { 'sign': 'RSA-SHA512' }
};

function doSign (SigStructure, signer, alg) {
  return new Promise((resolve, reject) => {
    if (!AlgFromTags[alg]) {
      throw new Error('Unknown algorithm, ' + alg);
    }
    if (!COSEAlgToNodeAlg[AlgFromTags[alg].sign]) {
      throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
    }

    let ToBeSigned = cbor.encode(SigStructure);

    let sig;
    if (AlgFromTags[alg].sign.startsWith('ES')) {
      const hash = crypto.createHash(COSEAlgToNodeAlg[AlgFromTags[alg].sign].digest);
      hash.update(ToBeSigned);
      ToBeSigned = hash.digest();
      const ec = new EC(COSEAlgToNodeAlg[AlgFromTags[alg].sign].sign);
      const key = ec.keyFromPrivate(signer.key.d);
      const signature = key.sign(ToBeSigned);
      const bitLength = Math.ceil(ec.curve._bitLength / 8);
      sig = Buffer.concat([signature.r.toArrayLike(Buffer, undefined, bitLength), signature.s.toArrayLike(Buffer, undefined, bitLength)]);
    } else {
      const sign = crypto.createSign(COSEAlgToNodeAlg[AlgFromTags[alg].sign].sign);
      sign.update(ToBeSigned);
      sign.end();
      sig = sign.sign(signer.key);
    }

    resolve(sig);
  });
}
 
exports.create = function (headers, payload, signers, options) {
  options = options || {};
  let u = headers.u || {};
  let p = headers.p || {};

  p = common.TranslateHeaders(p)
  u = common.TranslateHeaders(u);
  let bodyP = p || {};


  bodyP = (bodyP.size === 0) ? EMPTY_BUFFER : cbor.encode(bodyP);
  if (Array.isArray(signers)) {
    if (signers.length === 0) {
      throw new Error('There has to be at least one signer');
    }
    if (signers.length > 1) {
      throw new Error('Only one signer is supported');
    }
    // TODO handle multiple signers
    const signer = signers[0];
    const externalAAD = signer.externalAAD || EMPTY_BUFFER;
    let signerP = signer.p || {};
    let signerU = signer.u || {};

    signerP = common.TranslateHeaders(signerP);
    signerU = common.TranslateHeaders(signerU);
    const alg = signerP.get(common.HeaderParameters.alg);
    signerP = (signerP.size === 0) ? EMPTY_BUFFER : cbor.encode(signerP);

    const SigStructure = [
      'Signature',
      bodyP,
      signerP,
      externalAAD,
      payload
    ];
    return doSign(SigStructure, signer, alg).then((sig) => {
      if (p.size === 0 && options.encodep === 'empty') {
        p = EMPTY_BUFFER;
      } else {
        p = cbor.encode(p);
      }
      const signed = [p, u, payload, [[signerP, signerU, sig]]];
      return cbor.encode(options.excludetag ? signed : new Tagged(SignTag, signed));
    });
  } else {
    const signer = signers;
    const externalAAD = signer.external.AAD || EMPTY_BUFFER;
    const alg = p.get(common.HeaderParameters.alg) || u.get(common.HeaderParameters.alg);
    const SigStructure = [
      'Signature1',
      bodyP,
      externalAAD,
      payload
    ];
    return doSign(SigStructure, signer, alg).then((sig) => {
      if (p.size === 0 && options.encodep === 'empty') {
        p = EMPTY_BUFFER;
      } else {
        p = cbor.encode(p);
      }
      const signed = [p, u, payload, sig];
      return cbor.encodeCanonical(options.excludetag ? signed : new Tagged(Sign1Tag, signed));
    });
  }
};

function doVerify (SigStructure, verifier, alg, sig) {
  return new Promise((resolve, reject) => {
    if (!AlgFromTags[alg]) {
      throw new Error('Unknown algorithm, ' + alg);
    }
    if (!COSEAlgToNodeAlg[AlgFromTags[alg].sign]) {
      throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
    }
    const ToBeSigned = cbor.encode(SigStructure);

    if (AlgFromTags[alg].sign.startsWith('ES')) {
      const hash = crypto.createHash(COSEAlgToNodeAlg[AlgFromTags[alg].sign].digest);
      hash.update(ToBeSigned);
      const msgHash = hash.digest();

      const pub = { 'x': verifier.key.x, 'y': verifier.key.y };
      const ec = new EC(COSEAlgToNodeAlg[AlgFromTags[alg].sign].sign);
      const key = ec.keyFromPublic(pub);
      sig = { 'r': sig.slice(0, sig.length / 2), 's': sig.slice(sig.length / 2) };
      if (key.verify(msgHash, sig)) {
        resolve();
      } else {
        throw new Error('Signature missmatch');
      }
    } else {
      const verify = crypto.createVerify(COSEAlgToNodeAlg[AlgFromTags[alg].sign].sign);
      verify.update(ToBeSigned);
      if (verify.verify(verifier.key, sig)) {
        resolve();
      } else {
        throw new Error('Signature missmatch');
      }
    }
  });
}

function getSigner (signers, verifier) {
  for (let i = 0; i < signers.length; i++) {
    const kid = signers[i][1].get(common.HeaderParameters.kid); // TODO create constant for header locations
    if (kid.equals(Buffer.from(verifier.key.kid, 'utf8'))) {
      return signers[i];
    }
  }
}

function getCommonParameter (first, second, parameter) {
  let result;
  
  if (first.get) {
    result = first.get(parameter);
  }
  if (!result && second.get) {
    result = second.get(parameter);
  }
  return result;
}

exports.verify = function (payload, verifier, options) {
  options = options || {};
  return cbor.decodeFirst(payload)
    .then((obj) => {
      let type = options.defaultType ? options.defaultType : SignTag;
      if (obj instanceof Tagged) {
        if (obj.tag !== SignTag && obj.tag !== Sign1Tag) {
          throw new Error('Unexpected cbor tag, \'' + obj.tag + '\'');
        }
        type = obj.tag;
        obj = obj.value;
      }

      if (!Array.isArray(obj)) {
        throw new Error('Expecting Array');
      }

      if (obj.length !== 4) {
        throw new Error('Expecting Array of lenght 4');
      }

      let [p, u, plaintext, signers] = obj;

      if (type === SignTag && !Array.isArray(signers)) {
        throw new Error('Expecting signature Array');
      }

      p = (!p.length) ? EMPTY_BUFFER : cbor.decodeFirstSync(p);
      u = (!u.size) ? EMPTY_BUFFER : u;

      let signer = (type === SignTag ? getSigner(signers, verifier) : signers);

      if (!signer) {
        throw new Error('Failed to find signer with kid' + verifier.key.kid);
      }

      if (type === SignTag) {
        const externalAAD = verifier.externalAAD || EMPTY_BUFFER;
        let [signerP, , sig] = signer;
        signerP = (!signerP.length) ? EMPTY_BUFFER : signerP;
        p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
        const signerPMap = cbor.decode(signerP);
        const alg = signerPMap.get(common.HeaderParameters.alg);
        const SigStructure = [
          'Signature',
          p,
          signerP,
          externalAAD,
          plaintext
        ];
        return doVerify(SigStructure, verifier, alg, sig)
          .then(() => {
            return plaintext;
          });
      } else {
        const externalAAD = verifier.externalAAD || EMPTY_BUFFER;

        const alg = getCommonParameter(p, u, common.HeaderParameters.alg);
        p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
        const SigStructure = [
          'Signature1',
          p,
          externalAAD,
          plaintext
        ];
        return doVerify(SigStructure, verifier, alg, signer)
          .then(() => {
            return plaintext;
          });
      }
    });
};



class Sign{
  static Signtag = 98; 
  static Sign1Tag = 18;
  constructor(){
    this. EMPTY_BUFFER = common.EMPTY_BUFFER 
    this.AlgFromTags = {};
    this.COSEAlgToNodeAlg = {
      'ES256': { 'sign': 'p256', 'digest': 'sha256' },
      'ES384': { 'sign': 'p384', 'digest': 'sha384' },
      'ES512': { 'sign': 'p521', 'digest': 'sha512' },
      'RS256': { 'sign': 'RSA-SHA256' },
      'RS384': { 'sign': 'RSA-SHA384' },
      'RS512': { 'sign': 'RSA-SHA512' }
    } 
  }

  async doSign(SignStructure, alg, sig){
    if(!this.AlgFromTags[alg]){
      throw new Error('Unknown algorithm, ' + alg); 
    }

    if(!this.COSEAlgToNodeAlg[this.AlgFromTags[alg].sign]) {
      throw new Error("Unsupported algorithm", + this.AlgFromTags[alg].sign)
    }

    let ToBeSigned = cbor.encode(SignStructure)
    const data = this.AlgFromTags[alg].sign.startWith("ES")

    if(data){
      const hash = crypto.createHash(this.COSEAlgToNodeAlg[this.AlgFromTags[alg].sign].digest)
      hash.update(ToBeSigned)
      ToBeSigned = hash.digest()
      const ec = new EC(this.COSEAlgToNodeAlg[this.AlgFromTags[alg].sign].sign)
      const key = ec.keyFromPrivate(signer.key.d); 
      const signature = key.sign(ToBeSigned)
      const bitLength = Math.ceil(ec.curve._bitLength / 8)
     sig = Buffer.concat([signature.r.toArrayLike(Buffer, undefined, bitLength), signature.s.toArrayLike(Buffer, undefined, bitLength)]);
    
    }else {
      const sign = crypto.createSign(this.COSEAlgToNodeAlg[this.AlgFromTags[alg].sign].sign)
      sign.update(ToBeSigned)
      sign.end(); 
      sig = sign.sign(signer.key)
    }

    await sig
  }

  create(headers, payload, signers, option) {
    options = options || {};
    let u = headers.u || {};
    let p = headers.p || {};
    p = common.TranslateHeaders(p)
    u = common.TranslateHeaders(u)
    let bodyP = p || {};

    bodyP = (bodyP.size === 0) ? this.EMPTY_BUFFER : cbor.encode(bodyP);

    if(Array.isArray(signers)){
      if(signers.length === 0) throw new Error('There has to be at least one signer');
      if (signers.length > 1) throw new Error('Only one signer is supported');
    }

    const signer = signers[0]
    const externalAAD = signer.externalAAD || this.EMPTY_BUFFER
    let signerP = signer.p || {}; 
    let signerU = signer.u || {}; 

    signerP = common.TranslateHeaders(signerP)
    signerU = common.TranslateHeaders(signerU)

    const alg = signerP.get(common.HeaderParameters.alg)
    signerP = (signerP.size === 0) ? this.EMPTY_BUFFER : cbor.encode(signerP)
    const SigSignature = [
      'Signature', 
      bodyP, 
      signerP, 
      externalAAD, 
      payload
    ]; 

    doSign(SigSignature, signer, alg).then((sig) => {
      console.log('signer', sig)
      if(p.size === 0 && options.encodep === "empty"){
        p = this.EMPTY_BUFFER
      }else {
        p = cbor.encode(p)
      }
      const signed = [p, u, payload, [[signerP, signerU, sig]]]; 
      return cbor.encodeCanonical(options.excludetag ? signed : new Tagged(Sign1Tag, signed));
    })
  }

  getSigner(signers, verifier) {
    for(let i = 0; i<signers.length; i++) {
      const kid = signers[i][1].get(common.HeaderParameters.kid)  // TODO create constant for header locations
      const verifyKey = kid.equals(Buffer.from(verifier.key.kid, 'utf-8'))
      if(verifyKey) {
        return signers[1]; 
      }
    }
  }

  getCommonParameter(first, second, paramter){
    let result; 

    if(first.get){
      result = first.get(paramter)
    }

    if(!result && second.get){
      result = second.get(paramter); 
    }

    return result; 
  }

  async verify(payload, verifier, options){
    options = options || {}; 
    cbor.decodeFirst(payload).then((obj) => {
      let type = options.defaultType ? options.defaultType : Sign.Signtag; 
      if(obj instanceof Tagged){
        if(obj.tag !== Sign.SignTag && obj.tag !== Sign.Sign1Tag){
          throw new Error("Unexpected cbor tag, \"" + obj.tag + "\" ")
        }

        type = obj.tag; 
        obj = obj.value;
      }

      if(!Array.isArray(obj)){
        throw new Error("Expecting Array"); 
      }

      if(obj.length !== 4){
        throw new Error("Expecting Array of length 4")
      }
      
      let [p, u, plaintext, signers] = obj //destructing 

      if(type === Sign.SignTag && !Array.isArray(signers)){
        throw new Error('Expecting signature Array');
      }

      p = (!p.length) ? this.EMPTY_BUFFER : cbor.decodeFirstSync(p)
      u = (!u.size) ? this.EMPTY_BUFFER : u; 

      let signer = (type === Sign.SignTag ? this.getSigner(signers, verifier) : signers0)

      if(!signer){
        throw new Error("Failed to find signer with kid" + verifier.key.kid)
      }

      if(type === Sign.SignTag){
        const externalAAD = verifier.externalAAD || this.EMPTY_BUFFER
        let [signerP, , sig] = signer; 
        signerP = (!signerP.length) ? this.EMPTY_BUFFER : signerP; 
        p = (!p.size) ? this.EMPTY_BUFFER : cbor.encode(p); 
        const signerMap = cbor.decode(signerP); 
        const alg = signerMap.get(common.HeaderParameters.alg)
        const SigStructure = [
          'Signature', 
          p, 
          signerP, 
          externalAAD, 
          plaintext
        ]

        return this.doVerify(SigStructure, verifier, alg, sig)
            .then(() => {
              return plaintext
            })
      }else {
        const externalAAD = verifier.externalAAD || this.EMPTY_BUFFER; 
        const alg = await this.getCommonParameter(p, u, common.HeaderParameters.alg)
        p = (!p.size) ? this.EMPTY_BUFFER : cbor.encode(p); 
        const SigStructure = [
          'Signature1', 
          p,
          externalAAD, 
          plaintext
        ]

        return this.doVerify(SigStructure, verifier, alg, sig)
          .then(() => {
            return plaintext; 
          })
      }
    })
  }

  async doVerify(SignStructure, verifier, alg, sig){

  }
}


module.exports = Sign