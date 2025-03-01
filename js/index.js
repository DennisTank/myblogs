const blogList = document.getElementById("blog-list");
POSTS.forEach(post => {
    const li = document.createElement("li");
    li.innerHTML = `<button onclick="window.location.href='blog.html?id=${post}'">${post}</button>`;
    blogList.appendChild(li);
});