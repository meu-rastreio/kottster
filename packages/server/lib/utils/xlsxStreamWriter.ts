import { Writable } from 'stream';
import { Zip, ZipDeflate, ZipPassThrough, strToU8 } from 'fflate';

const CONTENT_TYPES_XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
  + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
  + '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
  + '<Default Extension="xml" ContentType="application/xml"/>'
  + '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
  + '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
  + '</Types>';

const ROOT_RELS_XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
  + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
  + '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
  + '</Relationships>';

const WORKBOOK_RELS_XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
  + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
  + '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
  + '</Relationships>';

const SHEET_HEADER_XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
  + '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>';

const SHEET_FOOTER_XML = '</sheetData></worksheet>';

// Characters not allowed in XML 1.0 documents
// eslint-disable-next-line no-control-regex
const INVALID_XML_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]/g;

/**
 * Minimal streaming writer for a single-sheet XLSX file.
 * Rows are written as soon as they are added, so large exports do not need to be kept in memory.
 */
export class XlsxStreamWriter {
  private readonly zip: Zip;
  private readonly sheet: ZipDeflate;
  private rowIndex = 0;
  private committed = false;

  constructor(output: Writable, sheetName: string = 'Sheet1') {
    this.zip = new Zip((error, chunk, final) => {
      if (error) {
        output.destroy(error);
        return;
      }
      output.write(chunk);
      if (final) {
        output.end();
      }
    });

    this.addStaticFile('[Content_Types].xml', CONTENT_TYPES_XML);
    this.addStaticFile('_rels/.rels', ROOT_RELS_XML);
    this.addStaticFile('xl/workbook.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
      + '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
      + `<sheets><sheet name="${this.escapeXml(sheetName.slice(0, 31))}" sheetId="1" r:id="rId1"/></sheets></workbook>`);
    this.addStaticFile('xl/_rels/workbook.xml.rels', WORKBOOK_RELS_XML);

    this.sheet = new ZipDeflate('xl/worksheets/sheet1.xml', { level: 6 });
    this.zip.add(this.sheet);
    this.sheet.push(strToU8(SHEET_HEADER_XML));
  }

  addRow(values: unknown[]) {
    if (this.committed) {
      throw new Error('Cannot add rows after the workbook was committed');
    }

    this.rowIndex++;
    const cells = values.map((value, index) => this.cellXml(`${this.columnName(index)}${this.rowIndex}`, value)).join('');
    this.sheet.push(strToU8(`<row r="${this.rowIndex}">${cells}</row>`));
  }

  commit() {
    if (this.committed) return;
    this.committed = true;

    this.sheet.push(strToU8(SHEET_FOOTER_XML), true);
    this.zip.end();
  }

  private addStaticFile(name: string, content: string) {
    const file = new ZipPassThrough(name);
    this.zip.add(file);
    file.push(strToU8(content), true);
  }

  private cellXml(ref: string, value: unknown): string {
    if (value === null || value === undefined || value === '') {
      return '';
    }
    if (typeof value === 'number' && Number.isFinite(value)) {
      return `<c r="${ref}"><v>${value}</v></c>`;
    }
    if (typeof value === 'boolean') {
      return `<c r="${ref}" t="b"><v>${value ? 1 : 0}</v></c>`;
    }

    const text = typeof value === 'object' ? JSON.stringify(value) : String(value);
    return `<c r="${ref}" t="inlineStr"><is><t xml:space="preserve">${this.escapeXml(text)}</t></is></c>`;
  }

  /**
   * Converts a zero-based column index into its spreadsheet name (0 => A, 26 => AA)
   */
  private columnName(index: number): string {
    let name = '';
    let n = index + 1;
    while (n > 0) {
      const remainder = (n - 1) % 26;
      name = String.fromCharCode(65 + remainder) + name;
      n = Math.floor((n - 1) / 26);
    }
    return name;
  }

  private escapeXml(text: string): string {
    return text
      .replace(INVALID_XML_CHARS, '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
}
