const form = document.getElementById('form');
const textInput = document.getElementById('text');
const amountInput = document.getElementById('amount');
const list = document.getElementById('rows');
const exportBtn = document.getElementById('export');

async function refresh() {
  const rows = await window.ledger.list();
  list.innerHTML = '';
  for (const row of rows) {
    const li = document.createElement('li');
    li.textContent = `${row.at.slice(5, 16)}  ${row.text}  ${row.amount}`;
    li.addEventListener('dblclick', async () => {
      await window.ledger.remove(row.id);
      refresh();
    });
    list.appendChild(li);
  }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  await window.ledger.add({ text: textInput.value, amount: amountInput.value });
  textInput.value = '';
  amountInput.value = '';
  refresh();
});

exportBtn.addEventListener('click', () => window.ledger.exportFile());

refresh();
