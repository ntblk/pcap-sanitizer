#!/usr/bin/env node

 const program = require('commander');
 const sani = require('./sanitize');

program
//  .version('0.0.0')
  .option('-p, --peppers', 'Add peppers')
  .option('-P, --pineapple', 'Add pineapple')
  .option('-b, --bbq-sauce', 'Add bbq sauce')
  .option('-c, --cheese [type]', 'Add the specified type of cheese [marble]', 'marble')
  .parse(process.argv);

async function run () {
  var files = program.args;
  files.forEach(f => sani(f));
}

run();
