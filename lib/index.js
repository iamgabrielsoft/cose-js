/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const Encrypt = require('./encrypt');
const Mac = require('./mac');
const Sign = require('./sign');



class Cose {
    constructor(){
        this.mac = new Mac()
        // this.sign = new Sign()
        this.encrypt = new Encrypt()
    }
}


module.exports = new Cose() //executor for users 