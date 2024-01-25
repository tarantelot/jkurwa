var fs = require('fs');
const {isPasswordCorrect} = require('../lib/util/check_password')


const key_path     = ""
const key_password = ''

try {
    const buff = fs.readFileSync(key_path);
  
    if (isPasswordCorrect(buff, key_password)){
      console.log('Password is correct!');
    } else {
      console.log('Password is incorrect!');
    }
} catch (err) {
  console.error('Error reading file:', err);
}