import * as fs from 'fs';
import * as path from 'path';
import { parse } from 'csv-parse/sync';
import { dirname } from 'path';
import { fileURLToPath } from 'url';

const currentDir = dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(currentDir, '../data');
fs.mkdirSync(dataDir, { recursive: true });

try {
  // Look for the correct dataset file at the root level
  const datasetPath = path.join(currentDir, '../../phising_and_legit_urls_dataset.csv');
  console.log('Reading from:', datasetPath);
  
  const dataset = fs.readFileSync(datasetPath, 'utf-8');
  const records = parse(dataset, { columns: true });

  // Debug: Check what columns we have
  console.log('CSV columns:', Object.keys(records[0]));
  console.log('First few records:', records.slice(0, 2));

  // Split and save using 'status' column instead of 'label'
  const phishingUrls = records.filter(r => r.status === '0').map(r => r.url);
  const legitUrls = records.filter(r => r.status === '1').map(r => r.url);

  // Debug: Count before writing
  console.log('Found URLs:', {
    total: records.length,
    phishing: phishingUrls.length,
    legitimate: legitUrls.length
  });

  fs.writeFileSync(path.join(dataDir, 'phishing.csv'), phishingUrls.join('\n'));
  fs.writeFileSync(path.join(dataDir, 'legitimate.csv'), legitUrls.join('\n'));

  console.log(`Created phishing.csv with ${phishingUrls.length} URLs`);
  console.log(`Created legitimate.csv with ${legitUrls.length} URLs`);
} catch (error) {
  console.error('Error:', error.message);
  console.log('Make sure phising_and_legit_urls_dataset.csv is in the project root directory');
  process.exit(1);
}
