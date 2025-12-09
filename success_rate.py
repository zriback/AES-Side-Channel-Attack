import find_key
import sys

SAMPLES = 10

def do_test(num_samples):
    results = []
    for i in range(SAMPLES):
        print(f'\nTest #{i}')
        result = find_key.find_key_success_rate(num_samples)
        results.append(result)
        print('DID IT!' if result else 'FAILED!')
    
    success_rate = sum(results) / len(results)

    print(f'\nOverall accuracy is {success_rate*100:.2f}% with {num_samples}')



if __name__ == '__main__':
    if len(sys.argv) != 1:
        print('Run this with a number of samples to test with')
    num_samples = int(sys.argv[1])

    do_test(num_samples)