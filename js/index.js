const blogList = document.getElementById("blog-list");
POSTS.forEach(post => {
    const li = document.createElement("li");
    li.innerHTML = `<a href="blog.html?id=${post}">${post}</a>`;
    blogList.appendChild(li);
});