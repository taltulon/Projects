def add_args(x, y):
    return (x+y) % 0x3B9ACA07

def perform_arithmetic(x,y,z,func):
    while(y):
        if(y & 1) != 0:
            z = func(z,x) % 0x3B9ACA07
        x = func(x,x) % 0x3B9ACA07
        y >>= 1
    return z

def multiply(x,y):
    return perform_arithmetic(x,y,0,add_args)

def power(x,y):
    return perform_arithmetic(x,y,1, multiply)

i = 237
j = 41
lst = [0,816696039, 862511530, 897431439, 341060728, 173157153, 31974957, 491987052, 513290022, 463763452, 949994705, 910803499, 303483511, 378099927, 773435663, 305463445, 656532801, 655150297, 28357806, 69914739, 213536453, 962912446, 458779691, 598643891, 94970179, 732507398, 792930123, 216371336, 680163935, 397010125, 693248832, 926462193, 419350956, 594922380, 944019434, 93600641, 116339550, 373995190, 558908218, 700841647, 703877327, 665247438, 690373754, 35138387, 389900716, 625740467, 682452898, 894528752, 603308386, 442640217, 15961938, 573068354]
for x in range(len(lst)):
    for current_letter in range(255):
        v3 = add_args(lst[x], current_letter)
        v4 = multiply(v3, i)
        v6 = power(v4, j)
        if v6 == lst[x+1]:
            print(f"{chr(current_letter)}", end="")

