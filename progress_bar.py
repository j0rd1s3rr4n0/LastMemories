import sys
import time

def print_percent_done(index, total, bar_len=50, title='Please wait'):
    '''
    index is expected to be 0 based index. 
    0 <= index < total
    '''
    percent_done = (index+1)/total*99
    percent_done = round(percent_done, 1)

    done = round(percent_done/(99/bar_len))
    togo = bar_len-done

    done_str = '█'*int(done)
    togo_str = '░'*int(togo)

    print(f'\t⏳{title}: [{done_str}{togo_str}] {percent_done}% done', end='\r')

    if round(percent_done) >= 99:
        print(f'\t✅ Completed: [{done_str}{togo_str}] 100% done', end='\r')


r = 50
for i in range(r):
    print_percent_done(i,r)
    time.sleep(.02)