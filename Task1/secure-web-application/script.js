async function login() {
    // 1. Get the values from the login.html input fields
    const usernameInput = document.getElementById("loginUsername").value;
    const passwordInput = document.getElementById("loginPassword").value;

    // 2. Send a POST request to your Node.js server
    const response = await fetch('/login_secure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: usernameInput, password: passwordInput })
    });

    // 3. Handle the server response
    if (response.ok) {
        const user = await response.json();
        // Save user info so the dashboard can display it
        localStorage.setItem("username", user.username);
        localStorage.setItem("role", user.role);
        window.location.href = "dashboard.html";
    } else {
        alert("Invalid username or password!");
    }
}

async function register() {
    const usernameInput = document.getElementById("regUsername").value;
    const passwordInput = document.getElementById("regPassword").value;

    const response = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: usernameInput, password: passwordInput })
    });

    const result = await response.json();
    alert(result.message);
    if (response.ok) {
        window.location.href = "login.html";
    }
}

async function logout() {
  localStorage.clear();

  await fetch('/logout', {
    method: 'POST'
  });

  window.location.href = "index.html";
}


// Keep this exactly as it is! 
// Using .innerHTML is the XSS vulnerability you need to fix in Part 2[cite: 1].
function addComment() {
  let input = document.getElementById("commentInput");
  let list = document.getElementById("commentsList");
  let li = document.createElement("li");
  li.innerHTML = input.value; 
  list.appendChild(li);
  input.value = "";
}

// This runs every time a page is loaded
window.onload = function() {
    // Check if we are on the dashboard page[cite: 3]
    if (document.getElementById("welcomeMessage")) {
        const storedName = localStorage.getItem("username");
        const storedRole = localStorage.getItem("role");

        if (storedName) {
            // Update the <h2> tag with the actual username
            document.getElementById("welcomeMessage").innerText = `Welcome, ${storedName}`;
            
            // If you want to update the role text as well:[cite: 3]
            const roleElement = document.querySelector("p"); 
            if (roleElement) {
                roleElement.innerText = `Role: ${storedRole}`;
            }
        }
    }
};

// ==============================================
// BIO Functions - XSS Vulnerable
// ==============================================

async function updateBio() {
    const bio = document.getElementById('bioInput').value;
    if (!bio) {
        alert("Please enter a bio!");
        return;
    }
    
    try {
        const response = await fetch('/update-bio', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ bio: bio })
        });
        
        const text = await response.text();

try {
    const result = JSON.parse(text);
    alert(result.message);
} catch {
    alert(text); // لو رجع HTML (مثلاً login page)
}
        document.getElementById('bioInput').value = '';
    } catch (error) {
        alert("Error: " + error);
    }
}

async function showAllBios() {
    window.open('/all-bios', '_blank');
}
