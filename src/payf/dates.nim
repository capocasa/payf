## Flexible date parsing for the `payf list` command and output escaping.

import std/[strutils, strformat, times, tables]

const MonthNames* = {
  "jan": 1, "january": 1,
  "feb": 2, "february": 2,
  "mar": 3, "march": 3,
  "apr": 4, "april": 4,
  "may": 5,
  "jun": 6, "june": 6,
  "jul": 7, "july": 7,
  "aug": 8, "august": 8,
  "sep": 9, "september": 9,
  "oct": 10, "october": 10,
  "nov": 11, "november": 11,
  "dec": 12, "december": 12
}.toTable

const DayNames* = {
  "mon": dMon, "monday": dMon,
  "tue": dTue, "tuesday": dTue,
  "wed": dWed, "wednesday": dWed,
  "thu": dThu, "thursday": dThu,
  "fri": dFri, "friday": dFri,
  "sat": dSat, "saturday": dSat,
  "sun": dSun, "sunday": dSun
}.toTable

proc lastDayOfMonth*(year, month: int): int =
  case month
  of 1, 3, 5, 7, 8, 10, 12: 31
  of 4, 6, 9, 11: 30
  of 2:
    if year mod 4 == 0 and (year mod 100 != 0 or year mod 400 == 0): 29
    else: 28
  else: 31

proc previousWeekday*(today: DateTime, target: WeekDay): DateTime =
  var d = today - 1.days
  while d.weekday != target:
    d = d - 1.days
  result = d

proc parseFlexDate*(s: string, isEndDate: bool): tuple[date: string, err: string] =
  let today = now()
  let todayDate = today.format("yyyyMMdd")
  let input = s.toLowerAscii.strip

  if input.len == 0:
    return (date: "", err: "")

  if input.len == 10 and input[4] == '-' and input[7] == '-':
    let normalized = input.replace("-", "")
    if normalized > todayDate:
      return (date: "", err: "Date " & input & " is in the future")
    return (date: normalized, err: "")

  if input.len == 8 and input.allCharsInSet({'0'..'9'}):
    if input > todayDate:
      return (date: "", err: "Date " & input & " is in the future")
    return (date: input, err: "")

  if input.endsWith("d") and input.len >= 2:
    let numPart = input[0..^2]
    try:
      let days = parseInt(numPart)
      let d = today - days.days
      return (date: d.format("yyyyMMdd"), err: "")
    except: discard

  case input
  of "today":
    return (date: todayDate, err: "")
  of "yesterday":
    return (date: (today - 1.days).format("yyyyMMdd"), err: "")
  of "week":
    let lastSunday = previousWeekday(today, dSun)
    let lastMonday = lastSunday - 6.days
    if isEndDate:
      return (date: lastSunday.format("yyyyMMdd"), err: "")
    else:
      return (date: lastMonday.format("yyyyMMdd"), err: "")
  of "month":
    var year = today.year
    var month = today.month.int - 1
    if month < 1:
      month = 12
      year -= 1
    if isEndDate:
      let lastDay = lastDayOfMonth(year, month)
      return (date: $year & align($month, 2, '0') & align($lastDay, 2, '0'), err: "")
    else:
      return (date: $year & align($month, 2, '0') & "01", err: "")
  of "year":
    let year = today.year - 1
    if isEndDate:
      return (date: $year & "1231", err: "")
    else:
      return (date: $year & "0101", err: "")
  of "ytd":
    if isEndDate:
      return (date: todayDate, err: "")
    else:
      return (date: $today.year & "0101", err: "")
  of "mtd":
    if isEndDate:
      return (date: todayDate, err: "")
    else:
      return (date: today.format("yyyyMM") & "01", err: "")
  else: discard

  if input in DayNames:
    let d = previousWeekday(today, DayNames[input])
    return (date: d.format("yyyyMMdd"), err: "")

  if input in MonthNames:
    let month = MonthNames[input]
    var year = today.year
    if month > today.month.int:
      year -= 1
    if isEndDate:
      let lastDay = lastDayOfMonth(year, month)
      return (date: $year & align($month, 2, '0') & align($lastDay, 2, '0'), err: "")
    else:
      return (date: $year & align($month, 2, '0') & "01", err: "")

  if input.len == 4 and input.allCharsInSet({'0'..'9'}):
    let year = parseInt(input)
    if year > today.year:
      return (date: "", err: "Year " & input & " is in the future")
    if isEndDate:
      if year == today.year:
        return (date: todayDate, err: "")
      return (date: input & "1231", err: "")
    else:
      return (date: input & "0101", err: "")

  var yearMonth = input.replace("-", "")
  if yearMonth.len == 6 and yearMonth.allCharsInSet({'0'..'9'}):
    let year = parseInt(yearMonth[0..3])
    let month = parseInt(yearMonth[4..5])
    if month < 1 or month > 12:
      return (date: "", err: "Invalid month: " & $month)
    let targetEnd = $year & align($month, 2, '0') & align($lastDayOfMonth(year, month), 2, '0')
    if targetEnd > todayDate:
      return (date: "", err: "Date " & input & " extends into the future")
    if isEndDate:
      let lastDay = lastDayOfMonth(year, month)
      let endDate = $year & align($month, 2, '0') & align($lastDay, 2, '0')
      if endDate > todayDate:
        return (date: todayDate, err: "")
      return (date: endDate, err: "")
    else:
      return (date: $year & align($month, 2, '0') & "01", err: "")

  var monthDay = input.replace("-", "")
  if monthDay.len == 4 and monthDay.allCharsInSet({'0'..'9'}):
    let month = parseInt(monthDay[0..1])
    let day = parseInt(monthDay[2..3])
    if month < 1 or month > 12:
      return (date: "", err: "Invalid month: " & $month)
    let maxDay = lastDayOfMonth(today.year, month)
    if day < 1 or day > maxDay:
      return (date: "", err: "Invalid day: " & $day & " for month " & $month)
    var year = today.year
    let targetDate = $year & align($month, 2, '0') & align($day, 2, '0')
    if targetDate > todayDate:
      year -= 1
    return (date: $year & align($month, 2, '0') & align($day, 2, '0'), err: "")

  if input.len == 2 and input.allCharsInSet({'0'..'9'}):
    let month = parseInt(input)
    if month >= 1 and month <= 12:
      var year = today.year
      if month > today.month.int:
        year -= 1
      if isEndDate:
        let lastDay = lastDayOfMonth(year, month)
        return (date: $year & align($month, 2, '0') & align($lastDay, 2, '0'), err: "")
      else:
        return (date: $year & align($month, 2, '0') & "01", err: "")

  return (date: "", err: "Unknown date format: " & s)

proc escapeField*(s: string, sep: char, quote: string): string =
  if quote.len > 0:
    result = quote & s.replace(quote, quote & quote) & quote
  else:
    if sep == '\t':
      result = s.replace("\t", "  ")
    else:
      result = s.replace($sep, " ")
    result = result.replace("\n", " ").replace("\r", "")

proc formatAmount*(amount: float): string =
  fmt"{amount:.2f}"
