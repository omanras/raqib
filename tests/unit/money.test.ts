import { describe, expect, it } from 'vitest';
import {
  CURRENCIES,
  MAX_AMOUNT,
  addAmounts,
  formatMinor,
  formatMoney,
  isAmount,
  minorUnitOf,
  mulAmount,
  parseAmount,
  sumAmounts,
} from '../../shared/money.js';

const ok = (text: string, unit: 2 | 3) => {
  const r = parseAmount(text, unit);
  if (!r.ok) throw new Error(`expected ${text} to parse, got ${r.error}`);
  return r.value;
};
const err = (text: string, unit: 2 | 3) => {
  const r = parseAmount(text, unit);
  if (r.ok) throw new Error(`expected ${text} to be refused, got ${r.value}`);
  return r.error;
};

describe('money.parseAmount', () => {
  it('reads integers and decimals into minor units', () => {
    expect(ok('0', 2)).toBe(0);
    expect(ok('12', 2)).toBe(1200);
    expect(ok('12.5', 2)).toBe(1250);
    expect(ok('12.50', 2)).toBe(1250);
    expect(ok('0.05', 2)).toBe(5);
    expect(ok('50', 3)).toBe(50000);
    expect(ok('50.125', 3)).toBe(50125);
    expect(ok('  7.1  ', 3)).toBe(7100);
  });

  it('accepts the documented grouping only', () => {
    expect(ok('1,234', 2)).toBe(123400);
    expect(ok('1,234,567.89', 2)).toBe(123456789);
    expect(err('1,23', 2)).toBe('grouping');
    expect(err('12,34,567', 2)).toBe('grouping');
    expect(err('1234,567', 2)).toBe('grouping');
    expect(err(',123', 2)).toBe('format');
    expect(err('0,123', 2)).toBe('grouping');
    expect(err('1.234,50', 2)).toBe('format');
    expect(err('1 234', 2)).toBe('format');
    expect(err("1'234", 2)).toBe('format');
  });

  it('reads Arabic-Indic digits and Arabic separators as Latin', () => {
    expect(ok('١٢٣', 3)).toBe(123000);
    expect(ok('١٢٫٥', 2)).toBe(1250);
    expect(ok('۱٬۲۳۴', 2)).toBe(123400);
  });

  it('rejects more decimals than the currency has', () => {
    expect(err('1.234', 2)).toBe('too_many_decimals');
    expect(err('1.2345', 3)).toBe('too_many_decimals');
    expect(err('0.001', 2)).toBe('too_many_decimals');
  });

  it('rejects signs, exponents, empty and malformed input', () => {
    expect(err('-1', 2)).toBe('sign');
    expect(err('+1', 2)).toBe('sign');
    expect(err('−1', 2)).toBe('sign');
    expect(err('1e3', 2)).toBe('exponent');
    expect(err('1E3', 2)).toBe('exponent');
    expect(err('', 2)).toBe('empty');
    expect(err('   ', 2)).toBe('empty');
    expect(err('.5', 2)).toBe('format');
    expect(err('5.', 2)).toBe('format');
    expect(err('1.2.3', 2)).toBe('format');
    expect(err('abc', 2)).toBe('format');
    expect(err('0x10', 2)).toBe('format');
    expect(err('Infinity', 2)).toBe('format');
    expect(err('NaN', 2)).toBe('format');
    expect(err('012', 2)).toBe('leading_zero');
  });

  it('rejects amounts above MAX_AMOUNT', () => {
    expect(err('1000000000000', 2)).toBe('too_large');
    expect(err('99999999999999999999', 2)).toBe('too_large');
    expect(ok('1000000000', 2)).toBe(MAX_AMOUNT);
  });
});

describe('money arithmetic', () => {
  it('sums and multiplies with overflow checks', () => {
    expect(sumAmounts([1, 2, 3])).toBe(6);
    expect(sumAmounts([])).toBe(0);
    expect(() => sumAmounts([Number.MAX_SAFE_INTEGER, 1])).toThrow(RangeError);
    expect(() => sumAmounts([1.5])).toThrow(RangeError);
    expect(addAmounts(5, 7)).toBe(12);
    expect(() => addAmounts(Number.MAX_SAFE_INTEGER, 1)).toThrow(RangeError);
    expect(mulAmount(50000, 12)).toBe(600000);
    expect(() => mulAmount(Number.MAX_SAFE_INTEGER, 2)).toThrow(RangeError);
    expect(() => mulAmount(1, -1)).toThrow(RangeError);
  });

  it('isAmount accepts non-negative safe integers up to MAX_AMOUNT', () => {
    expect(isAmount(0)).toBe(true);
    expect(isAmount(MAX_AMOUNT)).toBe(true);
    expect(isAmount(MAX_AMOUNT + 1)).toBe(false);
    expect(isAmount(-1)).toBe(false);
    expect(isAmount(1.5)).toBe(false);
    expect(isAmount('1')).toBe(false);
  });
});

describe('money.format', () => {
  it('formats per currency minor unit with Latin digits', () => {
    expect(formatMinor(123450, 3)).toBe('123.450');
    expect(formatMinor(5, 2)).toBe('0.05');
    expect(formatMinor(123456789, 2)).toBe('1,234,567.89');
    expect(formatMinor(123456789, 2, { grouping: false })).toBe('1234567.89');
    expect(formatMinor(-1250, 2)).toBe('-12.50');
    expect(formatMoney(50000, 'OMR')).toBe('50.000 OMR');
    expect(formatMoney(2500, 'USD')).toBe('25.00 USD');
  });

  it('parse(format(x)) is the identity for every currency (random, seeded)', () => {
    let s = 42;
    const rnd = () => {
      s = (s * 1103515245 + 12345) % 2147483648;
      return s;
    };
    for (const code of Object.keys(CURRENCIES)) {
      const unit = minorUnitOf(code);
      for (let i = 0; i < 50; i += 1) {
        const x = (rnd() * 97) % MAX_AMOUNT;
        expect(ok(formatMinor(x, unit), unit)).toBe(x);
      }
    }
  });

  it('knows the minor units of the Gulf currencies', () => {
    expect(minorUnitOf('OMR')).toBe(3);
    expect(minorUnitOf('KWD')).toBe(3);
    expect(minorUnitOf('BHD')).toBe(3);
    expect(minorUnitOf('SAR')).toBe(2);
    expect(minorUnitOf('AED')).toBe(2);
    expect(() => minorUnitOf('XXX')).toThrow(RangeError);
  });
});
