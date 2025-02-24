
function deletePassword(id) {
    if (confirm("Are you sure you want to delete this entry?")) {
        fetch(`/delete/${id}`, { method: "POST" })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                document.getElementById(`row-${id}`).remove(); // Remove entry from UI
            } else {
                alert("Failed to delete.");
            }
        });
    }
}
