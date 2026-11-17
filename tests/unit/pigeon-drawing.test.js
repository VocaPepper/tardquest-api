const { expect } = require('chai');
const config = require('../../src/config');
const { validateDrawing } = require('../../src/services/pigeon.service');
const { supportsPigeonDrawing } = require('../../src/utils/validation');

// Handdrawn picture payload: a bounded vector-stroke format, validated
// fail-closed. The text sanitizer must never see this, so it needs its own
// structural + size checks. These tests pin every bound and malformed-shape
// rejection so a hostile client cannot smuggle an oversized or ragged payload.
describe('pigeon drawing validation (unit)', () => {
  it('returns a null drawing for absent payloads', () => {
    expect(validateDrawing(null)).to.deep.equal({ drawing: null });
    expect(validateDrawing(undefined)).to.deep.equal({ drawing: null });
  });

  it('normalizes a valid drawing and stamps v:1', () => {
    const out = validateDrawing({ v: 99, strokes: [{ c: 0, p: [0, 0, 100, 100] }] });
    expect(out.error).to.equal(undefined);
    expect(out.drawing).to.deep.equal({ v: 1, strokes: [{ c: 0, p: [0, 0, 100, 100] }] });
  });

  it('rejects a non-object payload', () => {
    expect(validateDrawing('nope').error).to.equal('Invalid drawing payload');
    expect(validateDrawing(123).error).to.equal('Invalid drawing payload');
    expect(validateDrawing([{ c: 0, p: [0, 0] }]).error).to.equal('Invalid drawing payload');
  });

  it('requires a non-empty strokes array', () => {
    expect(validateDrawing({}).error).to.equal('Drawing requires at least one stroke');
    expect(validateDrawing({ strokes: [] }).error).to.equal('Drawing requires at least one stroke');
    expect(validateDrawing({ strokes: 'x' }).error).to.equal('Drawing requires at least one stroke');
  });

  it('rejects too many strokes', () => {
    const strokes = Array.from({ length: config.drawingMaxStrokes + 1 }, () => ({ c: 0, p: [0, 0, 1, 1] }));
    expect(validateDrawing({ strokes }).error).to.equal('Drawing has too many strokes');
  });

  it('rejects a malformed stroke', () => {
    expect(validateDrawing({ strokes: [5] }).error).to.equal('Invalid drawing stroke');
    expect(validateDrawing({ strokes: [null] }).error).to.equal('Invalid drawing stroke');
  });

  it('bounds the color index to 0..maxColors-1 and integer', () => {
    expect(validateDrawing({ strokes: [{ c: -1, p: [0, 0, 1, 1] }] }).error).to.equal('Invalid drawing color index');
    expect(validateDrawing({ strokes: [{ c: config.drawingMaxColors, p: [0, 0, 1, 1] }] }).error).to.equal('Invalid drawing color index');
    expect(validateDrawing({ strokes: [{ c: 1.5, p: [0, 0, 1, 1] }] }).error).to.equal('Invalid drawing color index');
  });

  it('requires an even, non-empty point array', () => {
    expect(validateDrawing({ strokes: [{ c: 0, p: [] }] }).error).to.equal('Invalid drawing points');
    expect(validateDrawing({ strokes: [{ c: 0, p: [5] }] }).error).to.equal('Invalid drawing points');
    expect(validateDrawing({ strokes: [{ c: 0, p: [1, 2, 3] }] }).error).to.equal('Invalid drawing points');
    expect(validateDrawing({ strokes: [{ c: 0, p: '0,0' }] }).error).to.equal('Invalid drawing points');
  });

  it('rejects a stroke with too many points', () => {
    const p = Array.from({ length: (config.drawingMaxPointsPerStroke + 1) * 2 }, () => 0);
    expect(validateDrawing({ strokes: [{ c: 0, p }] }).error).to.equal('Drawing stroke has too many points');
  });

  it('keeps every coordinate an in-range integer', () => {
    expect(validateDrawing({ strokes: [{ c: 0, p: [-1, 0, 1, 1] }] }).error).to.equal('Drawing point out of canvas bounds');
    expect(validateDrawing({ strokes: [{ c: 0, p: [0, 0, config.drawingCanvasSize + 1, 1] }] }).error).to.equal('Drawing point out of canvas bounds');
    expect(validateDrawing({ strokes: [{ c: 0, p: [0, 1.5, 1, 1] }] }).error).to.equal('Drawing point out of canvas bounds');
    // upper bound is inclusive: canvas-size itself is allowed
    expect(validateDrawing({ strokes: [{ c: 0, p: [0, 0, config.drawingCanvasSize, config.drawingCanvasSize] }] }).drawing).to.not.equal(undefined);
  });

  it('rejects when the serialized payload exceeds the byte cap', () => {
    // Max strokes x max points with the largest 3-digit coordinate overflows
    // the small byte cap even though every structural bound is respected.
    const p = Array.from({ length: config.drawingMaxPointsPerStroke * 2 }, () => config.drawingCanvasSize);
    const strokes = Array.from({ length: config.drawingMaxStrokes }, () => ({ c: 7, p }));
    expect(validateDrawing({ strokes }).error).to.equal('Drawing payload too large');
  });
});

describe('supportsPigeonDrawing (unit)', () => {
  let original;
  before(() => {
    original = config.pigeonDrawingMinClientVersion;
    config.pigeonDrawingMinClientVersion = '4.2.0';
  });
  after(() => {
    config.pigeonDrawingMinClientVersion = original;
  });

  it('allows clients at or above the minimum (patch-insensitive)', () => {
    expect(supportsPigeonDrawing('4.2.0')).to.equal(true);
    expect(supportsPigeonDrawing('4.2.7')).to.equal(true);
    expect(supportsPigeonDrawing('4.9.0')).to.equal(true);
    expect(supportsPigeonDrawing('5.0.0')).to.equal(true);
  });

  it('denies older clients', () => {
    expect(supportsPigeonDrawing('4.1.99')).to.equal(false);
    expect(supportsPigeonDrawing('3.0.251113')).to.equal(false);
  });

  it('fails closed on unknown/missing versions', () => {
    expect(supportsPigeonDrawing('4.2')).to.equal(false);
    expect(supportsPigeonDrawing('garbage')).to.equal(false);
    expect(supportsPigeonDrawing(null)).to.equal(false);
    expect(supportsPigeonDrawing(undefined)).to.equal(false);
    expect(supportsPigeonDrawing(42)).to.equal(false);
  });
});
