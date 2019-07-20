import matplotlib as mpl
mpl.use('Agg')

import matplotlib.pyplot as plt
print("Imported matplotlib")
print(plt)
import numpy as np
print("Imported numpy")
# Disable interactive mode
plt.ioff()

fig, axes = plt.subplots(nrows=1, ncols=2, figsize=(9, 4))
print("Got here")

# generate some random test data
all_data = [np.random.normal(0, std, 100) for std in range(6, 10)]

# plot violin plot
axes[0].violinplot(all_data,
                   showmeans=False,
                   showmedians=True)
axes[0].set_title('violin plot')

# plot box plot
axes[1].boxplot(all_data)
axes[1].set_title('box plot')

# adding horizontal grid lines
for ax in axes:
    ax.yaxis.grid(True)
    ax.set_xticks([y+1 for y in range(len(all_data))])
    ax.set_xlabel('xlabel')
    ax.set_ylabel('ylabel')

# add x-tick labels
plt.setp(axes, xticks=[y+1 for y in range(len(all_data))],
         xticklabels=['x1', 'x2', 'x3', 'x4'])
# plt.show()
print(plt)
plt.savefig("~/output.png")
