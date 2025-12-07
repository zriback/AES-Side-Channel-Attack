import find_key
import matplotlib.pyplot as plt

SAMPLES = 100

def main():
    results = []
    for i in range(SAMPLES):
        print(f'\nTest #{i}')
        results.append(find_key.find_key())

    # Find average number of samples required
    average = sum(results) / len(results)
    print(f'Average samples required: {average:.2f}')
    
    # Make a histogram of the results
    plt.hist(results, bins=20)
    plt.xlabel('Samples Required')
    plt.ylabel('Frequency')
    plt.title('Samples Required to Recover the Key')

    plt.show()


if __name__ == '__main__':
    main()