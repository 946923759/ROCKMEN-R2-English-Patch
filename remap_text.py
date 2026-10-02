import re
import sys
import os

remap_dictionary_ja = [
    "あいうえおかきくけこさしすせそたちつてとなにぬねのは",
    "アイウエオカキクケコサシスセソタチツテトナニヌネノハ"
]
remap_dictionary_en = [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "abcdefghijklmnopqrstuvwxyz"
]
manual_remap = {
    ".":"。",
    ",":"、",
    "?":"？",
    "!":"！",
    "￥":"￥", #Line break
    "*":"〇",
    " ":"ぉ",
    "'":"が",
    "-":"ー",
    "(":"（",
    ")":"）"
}
def remap_chr(c:str) -> str:
    for row in range(2):
        for col in range(len(remap_dictionary_en[row])):
            if c == remap_dictionary_en[row][col]:
                #print(remap_dictionary_ja[row][col])
                return remap_dictionary_ja[row][col]
    assert c in manual_remap, "Can't find remap for character "+c
    return manual_remap[c]

def remap_text(s:str) -> str:
    mutable_str = ['']*len(s)
    for i in range(len(s)):
        mutable_str[i] = remap_chr(s[i])
    return ''.join(mutable_str)

def remap_all_text(s:str) -> str:
    replace_lines = []
    for line in s.splitlines():
        new_line = line.strip()
        #if line.startswith("＊"):
        m = re.search("＊(.+)「(.+)」",new_line)
        if m:
            dialogue = m.group(2)
            for splits in dialogue.split("￥"):
                if len(splits) > 28:
                    print("This line is too long for the text box. Insert more line breaks:")
                    print(dialogue)
            if len(dialogue) > 100:
                print("The game can only draw 100 characters maximum... This line is too long:")
                print(dialogue)

            #remap = 
            # re.sub(r"＊(.+)「(.+)」",r"＊\1「\2」","＊Dr. Wily「Wahahaha!￥Falling for the same trick twice!」")
            new_line = re.sub(r"＊(.+)「(.+)」",r"＊\1「"+remap_text(dialogue)+"」",line)
        #print(new_line)
        replace_lines.append(new_line)
    return "\n".join(replace_lines)

def main():
    for file_name in os.listdir("in"):
        if file_name.endswith(".txt"):
            file_name_and_path = os.path.join("in",file_name)
            #print(file_name_and_path)
            #print(file_name)
            with open(file_name_and_path, encoding="utf-8") as in_f:
                remapped = remap_all_text(in_f.read())
                #print(remapped)
                with open(os.path.join("out",file_name), encoding='shift-jis', mode='w') as out_f:
                    out_f.write(remapped)
        #break

if __name__ == "__main__":
    main()