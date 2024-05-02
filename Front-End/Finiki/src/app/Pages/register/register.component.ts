import { Component, OnInit, inject } from '@angular/core';
import { AuthService } from '../../Services/auth.service';
import { RegisterRequest } from '../../Interfaces/register-request';
import { MatSnackBar } from '@angular/material/snack-bar';
import { Router } from '@angular/router';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrl: './register.component.scss'
})
export class RegisterComponent implements OnInit {
  hide: boolean = true;
  form!: FormGroup;

  constructor( private service: AuthService, private router: Router, private fb: FormBuilder, private matSnackBar: MatSnackBar) { }

  ngOnInit(): void {
    this.form = this.fb.group({
      fullName: ['', Validators.required],
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(6)]],
      status: ['', Validators.required],
      age: ['', Validators.required],
      roles: []
    });
  }

  register() {
    if (this.form.invalid) {
      return;
    }

    const rolesStr : string = this.form.value.roles;
    const roles : string[] = rolesStr.split(' ').map((role: string)=> role.trim());
    this.form.value.roles = roles;
    
    this.service.register(this.form.value).subscribe({
      next: (response) => {
        console.log(response);
        this.router.navigate(['/home'])
      },
      error: (err) => {
        console.log(err);
        this.matSnackBar.open(err.error.message, 'Close', {
          duration: 5000,
          horizontalPosition: 'center'
        });
      }
    });

}
}