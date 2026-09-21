/**
 * Time as a policy condition, and the two cases that make it awkward:
 * midnight, and daylight saving.
 *
 * Every assertion uses a fixed instant and an explicit zone, so these say the
 * same thing wherever they run. A test that depends on the machine's clock
 * would pass in one office and fail in another.
 */

import { describe, expect, it } from 'vitest';
import { isValidSchedule, isValidTimeZone, localNow, scheduleIsOpen } from '../src/schedule.ts';

const LONDON = 'Europe/London';
const KARACHI = 'Asia/Karachi';

/** Wednesday 2026-09-23, 12:00 UTC. */
const middayUtc = new Date('2026-09-23T12:00:00Z');

describe('reading the clock where the workspace is', () => {
  it('reports the local day and minute, not the server’s', () => {
    // Midday UTC is 13:00 in London (BST) and 17:00 in Karachi.
    expect(localNow(middayUtc, LONDON)).toEqual({ day: 3, minutes: 13 * 60 });
    expect(localNow(middayUtc, KARACHI)).toEqual({ day: 3, minutes: 17 * 60 });
  });

  it('follows daylight saving rather than a fixed offset', () => {
    // Same wall-clock hour, opposite sides of the UK's October change.
    const summer = new Date('2026-09-23T12:00:00Z');
    const winter = new Date('2026-12-23T12:00:00Z');
    expect(localNow(summer, LONDON).minutes).toBe(13 * 60);
    expect(localNow(winter, LONDON).minutes).toBe(12 * 60);
  });

  it('falls back to UTC for a zone it does not know', () => {
    // A rule should narrow when its clock is unreadable, never widen.
    expect(localNow(middayUtc, 'Mars/Olympus')).toEqual(localNow(middayUtc, 'UTC'));
  });

  it('knows a real zone from an invented one', () => {
    expect(isValidTimeZone(LONDON)).toBe(true);
    expect(isValidTimeZone('Mars/Olympus')).toBe(false);
  });
});

describe('an ordinary working-hours window', () => {
  const nineToFive = { from: '09:00', to: '17:00' };

  it('is open during the day, in the workspace’s zone', () => {
    // 13:00 London.
    expect(scheduleIsOpen(nineToFive, middayUtc, LONDON)).toBe(true);
  });

  it('is shut at the same instant in a zone where it is evening', () => {
    // 17:00 Karachi — the window closed exactly on the hour.
    expect(scheduleIsOpen(nineToFive, middayUtc, KARACHI)).toBe(false);
  });

  it('opens on the minute and closes on the minute', () => {
    const at = (iso: string) => scheduleIsOpen(nineToFive, new Date(iso), 'UTC');
    expect(at('2026-09-23T08:59:00Z')).toBe(false);
    expect(at('2026-09-23T09:00:00Z')).toBe(true);
    expect(at('2026-09-23T16:59:00Z')).toBe(true);
    // Closed *at* the end, not a minute after it.
    expect(at('2026-09-23T17:00:00Z')).toBe(false);
  });

  it('applies only on the days it names', () => {
    const weekdays = { ...nineToFive, days: [1, 2, 3, 4, 5] };
    // Wednesday, then Saturday.
    expect(scheduleIsOpen(weekdays, new Date('2026-09-23T12:00:00Z'), 'UTC')).toBe(true);
    expect(scheduleIsOpen(weekdays, new Date('2026-09-26T12:00:00Z'), 'UTC')).toBe(false);
  });
});

describe('a window that crosses midnight', () => {
  // A night shift, not a mistake.
  const nights = { from: '22:00', to: '06:00' };

  it('is open late on the evening it starts', () => {
    expect(scheduleIsOpen(nights, new Date('2026-09-23T23:00:00Z'), 'UTC')).toBe(true);
  });

  it('is open early the next morning', () => {
    expect(scheduleIsOpen(nights, new Date('2026-09-24T02:00:00Z'), 'UTC')).toBe(true);
  });

  it('is shut in the afternoon between them', () => {
    expect(scheduleIsOpen(nights, new Date('2026-09-24T14:00:00Z'), 'UTC')).toBe(false);
  });

  it('counts the morning against the day the shift began', () => {
    // A Friday-night shift is still a Friday shift at 02:00 on Saturday, and a
    // Sunday morning does not belong to a Monday-night rule.
    const fridayNights = { ...nights, days: [5] };
    expect(scheduleIsOpen(fridayNights, new Date('2026-09-25T23:00:00Z'), 'UTC')).toBe(true);
    expect(scheduleIsOpen(fridayNights, new Date('2026-09-26T02:00:00Z'), 'UTC')).toBe(true);
    expect(scheduleIsOpen(fridayNights, new Date('2026-09-26T23:00:00Z'), 'UTC')).toBe(false);
  });
});

describe('a window that cannot be read', () => {
  it('is shut, not open', () => {
    // Every one of these is a rule somebody got wrong. A malformed window that
    // defaulted to open would widen access by being broken.
    for (const bad of [
      { from: '25:00', to: '17:00' },
      { from: '09:00', to: '9:00' },
      { from: '', to: '17:00' },
      { from: '09:00', to: '09:00' },
      { from: '09:00', to: '17:00', days: [] },
      { from: '09:00', to: '17:00', days: [7] },
      { from: '09:00', to: '17:00', days: [-1] },
    ]) {
      expect(scheduleIsOpen(bad, middayUtc, 'UTC'), JSON.stringify(bad)).toBe(false);
      expect(isValidSchedule(bad), JSON.stringify(bad)).toBe(false);
    }
  });
});
