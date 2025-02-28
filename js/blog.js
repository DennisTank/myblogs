const params = new URLSearchParams(window.location.search);
const blogId = params.get("id");
console.log(blogId);
if (blogId) {
    fetch(`posts/${blogId}.md`)
        .then(response => response.ok ? response.text() : "Post not found.")
        .then(markdown => {
            document.getElementById("output").innerHTML = marked.parse(markdown);
        })
        .catch(() => document.getElementById("output").innerText = "Error loading post.");
} else {
    document.getElementById("output").innerText = "No post selected.";
}