var fs = require('fs');
const {isPasswordCorrect} = require('../lib/util/check_password')


const keyPath     = ""
const keyPassword = ''

try {
    const buff = fs.readFileSync(keyPath);
  
    if (isPasswordCorrect(buff, keyPassword)){
      console.log('Password is correct!');
    } else {
      console.log('Password is incorrect!');
    }
} catch (err) {
  console.error('Error reading file:', err);
}