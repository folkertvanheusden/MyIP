#include <pthread.h>
#include <stdint.h>

static constexpr int up_size = 100;

template <typename T>
class fifo
{
private:
	T *data { nullptr };
	const int n_elements;

	int read_pointer { 0 }, write_pointer { 0 };
	bool full { false };

	pthread_mutex_t lock;

	/* cond_push is signalled when a new item is pushed
	 * cond_pull is signalled when an item is removed
	 */
	pthread_cond_t cond_push, cond_pull;

	int up_divider { 1 };
	uint64_t usage_pattern[up_size] { 0 };

public:
	fifo(const int n_elements) : n_elements(n_elements)
	{
		data = new T[n_elements];

		up_divider = (n_elements + 1) / up_size;

		pthread_mutex_init(&lock, NULL);

		pthread_cond_init(&cond_push, NULL);
		pthread_cond_init(&cond_pull, NULL);
	}

	~fifo()
	{
		delete [] data;
	}

	void put(const T & element)
	{
		pthread_mutex_lock(&lock);

		while(full)
			pthread_cond_wait(&cond_pull, &lock);

		data[write_pointer] = *element;

		usage_pattern[write_pointer / up_divider]++;

		write_pointer++;
		write_pointer %= n_elements;

		full = write_pointer == read_pointer;

		pthread_cond_signal(&cond_push);

		pthread_mutex_unlock(&lock);
	}

	bool try_put(const T & element)
	{
		bool have_put = false;

		pthread_mutex_lock(&lock);

		if (!full) {
			data[write_pointer] = element;

			usage_pattern[write_pointer / up_divider]++;

			write_pointer++;
			write_pointer %= n_elements;

			full = write_pointer == read_pointer;

			have_put = true;

			pthread_cond_signal(&cond_push);
		}

		pthread_mutex_unlock(&lock);

		return have_put;
	}

	T get()
	{
		pthread_mutex_lock(&lock);

		while(read_pointer == write_pointer && !full)
			pthread_cond_wait(&cond_push, &lock);

		T copy = data[read_pointer];

		read_pointer++;
		read_pointer %= n_elements;

		full = 0;

		pthread_cond_signal(&cond_pull);

		pthread_mutex_unlock(&lock);

		return copy;
	}
};
