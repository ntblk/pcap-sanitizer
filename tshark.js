const fs = require('fs');
const execa = require('execa');
const _ = require('lodash');

async function get_ftypes () {
  var p;
  p = await execa.shell('tshark -G ftypes');

  //var data = p.stdout.split('\n').map(row => row.split('\t'));

  var colNames = ['name', 'desc'];
  var data = p.stdout.split('\n').map(row => _.zipObject(colNames, row.split('\t')));
  data.forEach((row, n) => row.id = n);

  return data;
}


async function get_decodes () {
  var p;
  p = await execa.shell('tshark -G decodes');

  //var data = p.stdout.split('\n').map(row => row.split('\t'));

  var colNames = ['layer_type', 'selector', 'name'];
  var data = p.stdout.split('\n').map(row => _.zipObject(colNames, row.split('\t')));

  var gdata = _.groupBy(data, 'layer_type');
  _.each(data, row => {
    row.selector = parseInt(row.selector, 10);
    delete row['layer_type'];
  });
  data = gdata;

  if (0)
  data = _.mapValues(data, field => {
    return _.groupBy(field, 'selector');
  });

  return data;
}


async function get_fields () {
  var p;
  p = await execa.shell('tshark -G fields');

  var colNames = ['layer_type', 'selector', 'name'];
  var data = p.stdout.split('\n').map(row => row.split('\t'));

  var gdata = _.groupBy(data, 0);
  /*
  _.each(data, row => {
    row.selector = parseInt(row.selector, 10);
    delete row['layer_type'];
  });
  */
  data = gdata;

  console.log(data);
  return data;
}


async function run () {
  var data = {};

  data.ftypes = await get_ftypes();
  data.decodes = await get_decodes();
  //data.fields = await get_fields();

  fs.writeFileSync('tables.json', JSON.stringify(data, null, 2), 'utf8');
}

run();
