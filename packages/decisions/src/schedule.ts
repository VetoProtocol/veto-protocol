/**
 * Time as a policy condition (spec FR-06).
 *
 * "Limit access by application, operation, resource, **time**, and volume." The
 * other four were there; this is the one that was not.
 *
 * ## A window narrows by not matching
 *
 * A rule outside its window does not apply. It does not deny, and it does not
 * challenge — it is simply not one of the rules in play, and the existing
 * "no rule said yes is a denial" handles the rest (invariant 2).
 *
 * That composes correctly with precedence: a `deny` rule with a window still
 * beats an `allow` while its window is open, and stops mattering when it
 * closes. A window that denied directly would outrank rules it was never meant
 * to interact with.
 *
 * It also means no new reason code. There are twenty-five and the spec fixes
 * the number; a request refused because every rule's window is shut is
 * genuinely "no rule allows this", which is what `TOOL_NOT_ALLOWED` says.
 *
 * ## The workspace's clock, not the server's
 *
 * Evaluated in the workspace's IANA zone. "09:00" means nine in the morning
 * where the people are, and keeps meaning that across daylight saving and
 * across a service that moves. An offset would have drifted by an hour in
 * October, silently, in the direction of allowing an hour nobody intended.
 */

/** `HH:MM`, 24-hour. Minutes, because an hour is too coarse for a shift end. */
export const TIME_PATTERN = /^([01]\d|2[0-3]):[0-5]\d$/;

export interface Schedule {
  /**
   * Days this applies on, 0 = Sunday. Omitted means every day.
   *
   * Explicit rather than "weekdays", because which days are a working week is
   * not the same everywhere and a rule should not have to know where it is.
   */
  readonly days?: readonly number[];
  readonly from: string;
  readonly to: string;
}

export const isValidSchedule = (schedule: Schedule): boolean =>
  TIME_PATTERN.test(schedule.from) &&
  TIME_PATTERN.test(schedule.to) &&
  schedule.from !== schedule.to &&
  (schedule.days === undefined ||
    (schedule.days.length > 0 &&
      schedule.days.length <= 7 &&
      schedule.days.every((day) => Number.isInteger(day) && day >= 0 && day <= 6)));

/** A zone name the runtime actually knows. Checked before it is stored. */
export function isValidTimeZone(timeZone: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone });
    return true;
  } catch {
    return false;
  }
}

const MINUTES = (time: string): number => {
  const [hours, minutes] = time.split(':');
  return Number(hours) * 60 + Number(minutes);
};

/**
 * What day and minute it is, where the workspace is.
 *
 * Derived through `Intl` rather than by arithmetic on an offset, so daylight
 * saving is the platform's problem and not a table somebody has to maintain.
 * An unknown zone falls back to UTC — a rule should narrow access when its
 * clock is unreadable, never widen it, and UTC is the one clock always
 * available.
 */
export function localNow(at: Date, timeZone: string): { day: number; minutes: number } {
  const zone = isValidTimeZone(timeZone) ? timeZone : 'UTC';
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: zone,
    hour12: false,
    weekday: 'short',
    hour: '2-digit',
    minute: '2-digit',
  }).formatToParts(at);

  const find = (type: string): string => parts.find((part) => part.type === type)?.value ?? '';
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

  // `hour: '2-digit'` with hour12:false renders midnight as "24" in some
  // runtimes. Both mean the same minute of the same day.
  const hour = Number(find('hour')) % 24;
  return {
    day: Math.max(0, days.indexOf(find('weekday'))),
    minutes: hour * 60 + Number(find('minute')),
  };
}

/**
 * Is the window open?
 *
 * A window whose end is before its start crosses midnight — "22:00 to 06:00" is
 * a night shift, not an error. The day is checked against the day the window
 * *opened*, so a shift that began on Friday stays a Friday shift at one in the
 * morning.
 */
export function scheduleIsOpen(schedule: Schedule, at: Date, timeZone: string): boolean {
  if (!isValidSchedule(schedule)) {
    // An unreadable window is not an open one. A malformed rule narrows.
    return false;
  }

  const { day, minutes } = localNow(at, timeZone);
  const from = MINUTES(schedule.from);
  const to = MINUTES(schedule.to);

  const onDay = (which: number): boolean =>
    schedule.days === undefined || schedule.days.includes(which);

  if (from < to) return minutes >= from && minutes < to && onDay(day);

  // Crosses midnight. Either it is late on a day the window opens, or early on
  // the morning after one.
  const yesterday = (day + 6) % 7;
  return (minutes >= from && onDay(day)) || (minutes < to && onDay(yesterday));
}
