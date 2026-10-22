// A heap with the worst retained value at the root. compare uses Array.sort order.
export class BoundedBuffer<T> {
  private readonly items: T[] = [];

  constructor(private readonly capacity: number, private readonly compare: (a: T, b: T) => number) {}

  get size(): number { return this.items.length; }

  add(item: T): void {
    if (this.capacity <= 0) return;
    if (this.size < this.capacity) {
      this.items.push(item);
      let child = this.size - 1;
      while (child > 0) {
        const parent = Math.floor((child - 1) / 2);
        if (this.compare(this.items[child], this.items[parent]) <= 0) break;
        [this.items[parent], this.items[child]] = [this.items[child], this.items[parent]];
        child = parent;
      }
      return;
    }
    if (this.compare(item, this.items[0]) >= 0) return;
    this.items[0] = item;
    let parent = 0;
    while (parent * 2 + 1 < this.size) {
      let child = parent * 2 + 1;
      if (child + 1 < this.size && this.compare(this.items[child + 1], this.items[child]) > 0) child++;
      if (this.compare(this.items[parent], this.items[child]) >= 0) break;
      [this.items[parent], this.items[child]] = [this.items[child], this.items[parent]];
      parent = child;
    }
  }

  sorted(): T[] { return this.items.slice().sort(this.compare); }
}
