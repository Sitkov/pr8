
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using pr8.Models;

namespace pr8.Controllers;

[Route("api/v1/[controller]")]
[ApiController]
[Authorize]
public class TasksController : ControllerBase
{
    private readonly Models.Pr8DbContext _db;

    public TasksController(Models.Pr8DbContext db)
    {
        _db = db;
    }

    [HttpGet]
    public IActionResult GetMyTasks()
    {
        var login = User.Identity?.Name;
        if (string.IsNullOrEmpty(login)) return Unauthorized();

        var tasks = _db.Tasks.Where(t => t.OwnerLogin == login).ToList();
        return Ok(tasks);
    }

    [HttpGet("{id:int}")]
    public IActionResult GetById(int id)
    {
        var task = _db.Tasks.Find(id);
        if (task == null) return NotFound("Задача не найдена");

        var login = User.Identity?.Name;
        bool isAdmin = User.IsInRole("Admin");

        if (task.OwnerLogin != login && !isAdmin)
            return Forbid(); // 403

        return Ok(task); // 200
    }

    [HttpPost]
    public IActionResult Create([FromBody] CreateTaskRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Title))
            return BadRequest("Название обязательно");

        var login = User.Identity?.Name;
        if (string.IsNullOrEmpty(login)) return Unauthorized();

        var task = new pr8.Models.Task
        {
            Title = request.Title.Trim(),
            Description = request.Description,
            OwnerLogin = login,
            IsCompleted = false
        };

        _db.Tasks.Add(task);
        _db.SaveChanges();

        return CreatedAtAction(nameof(GetById), new { id = task.Id }, task); // 201
    }

    [HttpPut("{id:int}")]
    public IActionResult Update(int id, [FromBody] UpdateTaskRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Title))
            return BadRequest("Название обязательно");

        var task = _db.Tasks.Find(id);
        if (task == null) return NotFound("Задача не найдена"); // 404

        var login = User.Identity?.Name;
        bool isAdmin = User.IsInRole("Admin");

        if (task.OwnerLogin != login && !isAdmin)
            return Forbid();

        task.Title = request.Title.Trim();
        task.Description = request.Description;
        task.IsCompleted = request.IsCompleted;

        _db.SaveChanges();

        return Ok(task);
    }

    [HttpDelete("{id:int}")]
    public IActionResult Delete(int id)
    {
        var task = _db.Tasks.Find(id);
        if (task == null) return NotFound("Задача не найдена");

        var login = User.Identity?.Name;
        bool isAdmin = User.IsInRole("Admin");

        if (task.OwnerLogin != login && !isAdmin)
            return Forbid();

        _db.Tasks.Remove(task);
        _db.SaveChanges();

        return NoContent(); // 204
    }

    [HttpGet("all")]
    [Authorize(Roles = "Admin")]
    public IActionResult GetAllTasks()
    {
        var allTasks = _db.Tasks.ToList();
        return Ok(allTasks);
    }
}

public class CreateTaskRequest
{
    public string Title { get; set; } = string.Empty;
    public string? Description { get; set; }
}

public class UpdateTaskRequest
{
    public string Title { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsCompleted { get; set; }
}
