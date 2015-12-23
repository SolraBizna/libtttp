-- This is kinda messy. Not meant to be modified by anyone but me.

local footnotemap = {ascii=1,mod=2,meta=3,numlockdep=4,intl=5,ee=6,wtf=7,calc=8,clearoverload=9,pausebrk=10}

local asciimap = {}

local function spleef(text)
   local ret = {(text:gsub(" OR "," / "))}
   if asciimap[text] then ret[2] = text.." (scan)" else ret[2] = text end
   return ret
end

local function footnote(text, ...)
   if type(text) == "string" then text = spleef(text) end
   local arg = {...}
   assert(#arg > 0)
   for n=1,#arg do
      arg[n] = "<a href=\"#foot"..assert(footnotemap[arg[n]], arg[n]).."\">"..footnotemap[arg[n]].."</a>"
   end
   return {text[1].."<sup>"..table.concat(arg,";").."</sup>", text[2]}
end

local function safe(text)
   if type(text) == "string" then text = spleef(text) end
   return {"<span class=\"safe\">"..text[1].."</span>", text[2]}
end

local codetable = {
   [8]="Backspace", [9]="Tab", [10]="Enter", [27]="Escape", [32]="Space",
   [127]="Delete",
}
for n=0x21,0x7E do
   if n < 0x61 or n > 0x7a then codetable[n] = string.char(n) end
end
for k,v in pairs(codetable) do asciimap[v] = k end

local usagetable = {
   [0]=nil, -- Reserved
   nil, -- ErrorRollOver status
   nil, -- POSTFail status
   nil, -- ErrorUndefined status
   footnote("A","ascii"),
   footnote("B","ascii"),
   footnote("C","ascii"),
   footnote("D","ascii"),
   footnote("E","ascii"),
   footnote("F","ascii"),
   footnote("G","ascii"),
   footnote("H","ascii"),
   footnote("I","ascii"),
   footnote("J","ascii"),
   footnote("K","ascii"),
   footnote("L","ascii"),
   footnote("M","ascii"),
   footnote("N","ascii"),
   footnote("O","ascii"),
   footnote("P","ascii"),
   footnote("Q","ascii"),
   footnote("R","ascii"),
   footnote("S","ascii"),
   footnote("T","ascii"),
   footnote("U","ascii"),
   footnote("V","ascii"),
   footnote("W","ascii"),
   footnote("X","ascii"),
   footnote("Y","ascii"),
   footnote("Z","ascii"),
   footnote("1","ascii"),
   footnote("2","ascii"),
   footnote("3","ascii"),
   footnote("4","ascii"),
   footnote("5","ascii"),
   footnote("6","ascii"),
   footnote("7","ascii"),
   footnote("8","ascii"),
   footnote("9","ascii"),
   footnote("0","ascii"),
   footnote("Enter","ascii"),
   footnote("Escape","ascii"),
   footnote("Backspace","ascii"),
   footnote("Tab","ascii"),
   footnote("Space","ascii"),
   footnote("-","ascii"),
   footnote("=","ascii"),
   footnote("[","ascii"),
   footnote("]","ascii"),
   footnote("\\","ascii"),
   footnote("#","ascii"),
   footnote(";","ascii"),
   footnote("'","ascii"),
   footnote("`","ascii"),
   footnote(",","ascii"),
   footnote(".","ascii"),
   footnote("/","ascii"),
   nil, -- Caps Lock
   safe"F1",
   safe"F2",
   safe"F3",
   safe"F4",
   safe"F5",
   safe"F6",
   safe"F7",
   safe"F8",
   safe"F9",
   safe"F10",
   safe"F11",
   safe"F12",
   "PrintScreen",
   nil, -- Scroll Lock
   footnote("Pause","pausebrk"),
   "Insert",
   "Home",
   "Page Up",
   footnote("Delete","ascii"),
   "End",
   "Page Down",
   "Right",
   "Left",
   "Down",
   "Up",
   footnote("Keypad Clear","clearoverload"),
   footnote("Keypad /","numlockdep"),
   footnote("Keypad *","numlockdep"),
   footnote("Keypad -","numlockdep"),
   footnote("Keypad +","numlockdep"),
   footnote("Keypad Enter","numlockdep"),
   footnote("Keypad 1 OR End","numlockdep"),
   footnote("Keypad 2 OR Down","numlockdep"),
   footnote("Keypad 3 OR Page Down","numlockdep"),
   footnote("Keypad 4 OR Left","numlockdep"),
   footnote("Keypad 5","numlockdep"),
   footnote("Keypad 6 OR Right","numlockdep"),
   footnote("Keypad 7 OR Home","numlockdep"),
   footnote("Keypad 8 OR Up","numlockdep"),
   footnote("Keypad 9 OR Page Up","numlockdep"),
   footnote("Keypad 0 OR Insert","numlockdep"),
   footnote("Keypad . OR Delete","numlockdep"),
   footnote("Non-US \\","ascii"),
   "Application",
   nil, -- Power status
   footnote("Keypad =","numlockdep"),
   "F13",
   "F14",
   "F15",
   "F16",
   "F17",
   "F18",
   "F19",
   "F20",
   "F21",
   "F22",
   "F23",
   "F24",
   "Execute",
   "Help",
   "Menu",
   "Select",
   "Stop",
   "Again",
   "Undo",
   "Cut",
   "Copy",
   "Paste",
   "Find",
   "Mute",
   "Volume Up",
   "Volume Down",
   footnote("Caps Lock","mod"),
   footnote("Num Lock","mod"),
   footnote("Scroll Lock","mod"),
   footnote("Keypad ,","numlockdep"),
   footnote("Keypad Equal Sign","numlockdep"),
   footnote("International1","intl"),
   footnote("International2","intl"),
   footnote("International3","intl"),
   footnote("International4","intl"),
   footnote("International5","intl"),
   footnote("International6","intl"),
   footnote("International7","intl"),
   footnote("International8","intl"),
   footnote("International9","intl"),
   footnote("Language1","intl"),
   footnote("Language2","intl"),
   footnote("Language3","intl"),
   footnote("Language4","intl"),
   footnote("Language5","intl"),
   footnote("Language6","intl"),
   footnote("Language7","intl"),
   footnote("Language8","intl"),
   footnote("Language9","intl"),
   footnote("Alt Erase","ee"),
   "SysReq",
   "Cancel",
   "Clear",
   "Prior",
   footnote("Return","wtf"),
   "Separator",
   "Out",
   "Oper",
   "Clear or Again",
   "CrSel OR Props",
   "ExSel",
   -- reserved block
   nil,
   nil,
   nil,
   nil,
   nil,
   nil,
   nil,
   nil,
   nil,
   nil,
   nil,
   footnote("Keypad 00","calc"),
   footnote("Keypad 000","calc"),
   footnote("Thousands Separator","calc"),
   footnote("Decimal Separator","calc"),
   footnote("Currency Unit","calc"),
   footnote("Currency Subunit","calc"),
   footnote("Keypad (","calc"),
   footnote("Keypad )","calc"),
   footnote("Keypad {","calc"),
   footnote("Keypad }","calc"),
   footnote("Keypad Tab","calc"),
   footnote("Keypad Backspace","calc"),
   footnote("Keypad A","calc"),
   footnote("Keypad B","calc"),
   footnote("Keypad C","calc"),
   footnote("Keypad D","calc"),
   footnote("Keypad E","calc"),
   footnote("Keypad F","calc"),
   footnote("Keypad XOR","calc"),
   footnote("Keypad ^","calc"),
   footnote("Keypad %","calc"),
   footnote("Keypad <","calc"),
   footnote("Keypad >","calc"),
   footnote("Keypad &","calc"),
   footnote("Keypad &&","calc"),
   footnote("Keypad |","calc"),
   footnote("Keypad ||","calc"),
   footnote("Keypad :","calc"),
   footnote("Keypad #","calc"),
   footnote("Keypad Space","calc"),
   footnote("Keypad @","calc"),
   footnote("Keypad !","calc"),
   footnote("Keypad Memory Store","calc"),
   footnote("Keypad Memory Recall","calc"),
   footnote("Keypad Memory Clear","calc"),
   footnote("Keypad Memory Add","calc"),
   footnote("Keypad Memory Subtract","calc"),
   footnote("Keypad Memory Multiply","calc"),
   footnote("Keypad Memory Divide","calc"),
   footnote("Keypad +/-","calc"),
   footnote("Keypad Clear (alt)","calc"),
   footnote("Keypad Clear Entry","calc"),
   footnote("Keypad Binary","calc"),
   footnote("Keypad Octal","calc"),
   footnote("Keypad Decimal","calc"),
   footnote("Keypad Hexadecimal","calc"),
   -- reserved block
   nil,
   nil,
   [0xE0]=footnote("Left Control","mod"),
   [0xE1]=footnote("Left Shift","mod"),
   [0xE2]=footnote("Left Alt","mod"),
   [0xE3]=footnote("Left GUI","mod","meta"),
   [0xE4]=footnote("Right Control","mod"),
   [0xE5]=footnote("Right Shift","mod"),
   [0xE6]=footnote("Right Alt","mod"),
   [0xE7]=footnote("Right GUI","mod","meta"),
   -- remainder is reserved
}

local abbreviations = {
   International="Int",
   Language="Lang",
   Keypad="KP",
   PrintScreen="PrntScr",
   Separator="Sep",
   Decimal="Dec",
   Octal="Oct",
   Binary="Bin",
   Hexadecimal="Hex",
   Memory="Mem",
   Subtract="Sub",
   Multiply="Mul",
   Divide="Div",
}

for k,v in pairs(codetable) do
   if type(v) == "string" then codetable[k] = {v,v} end
end
for k,v in pairs(usagetable) do
   if type(v) == "string" then codetable[k+128] = spleef(v)
   else codetable[k+128] = v end
end
for long,short in pairs(abbreviations) do
   abbreviations[long] = "<abbr title=\""..long.."\">"..short.."</abbr>"
end
local usednames = {}
local symnames = {
   ["!"]="EXCLAMATION_MARK",
   ["\""]="DOUBLE_QUOTE",
   ["#"]="NUMBER_SIGN",
   ["$"]="DOLLAR",
   ["%"]="PERCENT",
   ["&"]="AMPERSAND",
   ["'"]="SINGLE_QUOTE",
   ["("]="LEFT_PARENTHESIS",
   [")"]="RIGHT_PARENTHESIS",
   ["*"]="ASTERISK",
   ["+"]="PLUS",
   [","]="COMMA",
   ["-"]="HYPHEN",
   ["."]="PERIOD",
   ["/"]="SLASH",
   [":"]="COLON",
   [";"]="SEMICOLON",
   ["<"]="LESS_THAN",
   ["="]="EQUAL",
   [">"]="GREATER_THAN",
   ["?"]="QUESTION_MARK",
   ["@"]="AT",
   ["["]="LEFT_BRACKET",
   ["\\"]="BACKSLASH",
   ["]"]="RIGHT_BRACKET",
   ["^"]="CARET",
   ["_"]="UNDERSCORE",
   ["`"]="GRAVE",
   ["{"]="LEFT_CURLY_BRACE",
   ["|"]="VERTICAL_LINE",
   ["}"]="RIGHT_CURLY_BRACE",
   ["~"]="TILDE",
}
local codes = {}
for k,v in pairs(codetable) do
   for long,short in pairs(abbreviations) do
      v[1] = v[1]:gsub(long,short)
   end
   v[3] = v[2]:gsub(" OR .*$",""):upper():gsub(" %(SCAN%)$"," SCAN"):gsub(" %(ALT%)$"," ALT"):gsub("[!-/:-@[-`{-~]",symnames):gsub(" ","_")
   if usednames[v[3]] then
      error(("Name repeats: %s (0x%03x, 0x%03x)"):format(v[3], usednames[v[3]], k))
   else
      usednames[v[3]] = k
      table.insert(codes, {k,v[3],v[2]})
   end
end
table.sort(codes, function(a,b) return a[1] < b[1] end)

local f = io.open("tttp_scancodes.h", "w")
f:write[[
#ifndef TTTP_SCANCODES_H
#define TTTP_SCANCODES_H

#if __cplusplus
extern "C" {
#endif

enum tttp_scancode {
  KEY_INVALID = 0x000, // "no scancode", for use in APIs only
]]

for n=1,#codes do
   f:write(("  KEY_%s = 0x%03x,\n"):format(codes[n][2], codes[n][1]))
end
f:write(("  TTTP_HIGHEST_SCANCODE = 0x%03x\n"):format(codes[#codes][1]))

f:write[[
};

// Returns a (static) human-readable name for the scancode
const char* tttp_name_for_scancode(enum tttp_scancode code);
// Returns the KEY_* name for the scancode
const char* tttp_identifier_for_scancode(enum tttp_scancode code);

#if __cplusplus
}
#endif

#endif
]]
f:close()

f = io.open("tttp_scancodes.c","w")
f:write[[
#include "tttp_scancodes.h"
#include <stdlib.h>

const char* tttp_name_for_scancode(enum tttp_scancode code) {
  switch(code) {
]]
for n=1,#codes do
   f:write(("  case KEY_%s: return %q;\n"):format(codes[n][2], codes[n][3]))
end
f:write[[
  default: return NULL;
  }
}

const char* tttp_identifier_for_scancode(enum tttp_scancode code) {
  switch(code) {
]]
for n=1,#codes do
   f:write(("  case KEY_%s: return %q;\n"):format(codes[n][2], "KEY_"..codes[n][2]))
end
f:write[[
  default: return NULL;
  }
}
]]
f:close()

f = io.open("doc/scancodes.html","w")
f:write[[
<html>
<head>
<title>TTTP Scancodes</title>
<link rel="stylesheet" type="text/css" href="css.css"></link>
</head>
<body>
<p>Here is a list of relevant scancodes for TTTP keyboard messages. The ones from 0x00-0x7F correspond 1:1 with ASCII characters or control codes; the rest correspond 1:1 to usages from the USB HID Keyboard/Keypad page, plus 128. If a scancode is not in this table, a client should not generate it, and a server should disregard it.</p>
<p>Note: There is no Break scancode. USB keyboards with a Break key send a left control press (ONLY if it was not already pressed), a Pause press, a Pause release, and a left control release (ONLY if it was not already pressed). This is irrelevant to TTTP as Break must always quit the client.</p>
<table>
<thead><tr><th rowspan="2">&nbsp;</th><th class="evencol">0</th><th>1</th><th class="evencol">2</th><th>3</th><th class="evencol">4</th><th>5</th><th class="evencol">6</th><th>7</th></tr><tr><th class="evencol">8</th><th>9</th><th class="evencol">A</th><th>B</th><th class="evencol">C</th><th>D</th><th class="evencol">E</th><th>F</th></tr></thead>
<tbody>
]]
for n=0,22 do
   local rowtype
   if n % 2 == 0 then rowtype = "even" else rowtype = "odd" end
   f:write(("<tr class=\"%srow\"><th rowspan=\"2\">0x%02Xx</th>"):format(rowtype, n))
   local base = n*16
   for m=base,base+7 do
      local celltype
      if m % 2 == 0 then celltype = rowtype.."even" else celltype = rowtype.."odd" end
      if codetable[m] then
         f:write(("<td class=\"%s\">%s</td>"):format(celltype, codetable[m][1]))
      else
         f:write(("<td class=\"%s\">&nbsp;</td>"):format(celltype))
      end
   end
   f:write(("</tr><tr class=\"%srow\">"):format(rowtype))
   for m=base+8,base+15 do
      local celltype
      if m % 2 == 0 then celltype = rowtype.."even" else celltype = rowtype.."odd" end
      if codetable[m] then
         f:write(("<td class=\"%s\">%s</td>"):format(celltype, codetable[m][1]))
      else
         f:write(("<td class=\"%s\">&nbsp;</td>"):format(celltype))
      end
   end
end
f:write[[
</tbody>
</table>
<ol>
<li><a name="foot1"></a>These keys will normally generate corresponding ASCII-mapped codes, possibly in a layout-dependent way.</li>
<li><a name="foot2"></a>The various Lock keys act as modifiers. The client sends a press when the modifier becomes active, and a release when it becomes inactive. Modifiers should never change which scancodes are <i>sent</i>---for inputting text, 'Text' messages should be used. (Exception: Num Lock and keypad keys.)</li>
<li><a name="foot3"></a>The GUI key corresponds to the Windows key on Windows keyboards, the Command key on Apple keyboards, and the Meta key on awesome keyboards. You should not count on this key being available.</li>
<li><a name="foot4"></a>Keypad keys may instead generate ASCII-mapped codes, depending on the state of Num Lock in a client-specific way.</li>
<li><a name="foot5"></a>These keys are normally of interest only to IME.</li>
<li><a name="foot6"></a>This corresponds to the "left space" AKA "Eaze-Erase&#8482;" key on certain keyboards.</li>
<li><a name="foot7"></a>The Return key should normally be indistinguishable from Enter, and send a newline instead.</li>
<li><a name="foot8"></a>These keys are normally found only on "math keypads", e.g. calculators.</li>
<li><a name="foot9"></a>The Clear key corresponds to Num Lock on most PC keyboards, and will therefore unavoidably toggle Num Lock. This sucks.</li>
<li><a name="foot10"></a>This is not mentioned in the standards, but most PC keyboards do not generate a release for the Pause key. Most OSes synthesize one. Client authors should check to make sure this is done, and if it isn't, they MUST synthesize one themselves.</li>
</ol>
</body>
</html>
]]
f:close()
