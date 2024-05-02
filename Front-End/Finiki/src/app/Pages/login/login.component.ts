import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatSnackBar } from '@angular/material/snack-bar';
import { Router } from '@angular/router';
import { AuthService } from '../../Services/auth.service';
import { jwtDecode } from 'jwt-decode';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {
  hide = true;
  form!: FormGroup;
  decodedToken: any | null;
  tokenKey = 'token';
  tokenDecoded: any;

  constructor(
    private matSnackBar: MatSnackBar,
    private router: Router,
    private fb: FormBuilder,
    private authService: AuthService
  ) { }

  ngOnInit(): void {
    this.form = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', Validators.required],
    });

    this.tokenDecoded = jwtDecode(localStorage.getItem(this.tokenKey)!);
    console.log('decoded token');
    console.log(this.tokenDecoded);
    console.log('data kelyabdi');
    console.log(Date.now());

    if (this.tokenDecoded.exp * 1000 < Date.now()) {
      this.matSnackBar.open('Login again', 'Close', {
        duration: 5000,
        horizontalPosition: 'center'
      });
      this.router.navigate(['/login']); // changed because couldnt access to login page anymore after expiration
    }
  }

  login(): void {
    console.log("hi");
    this.authService.login(this.form.value).subscribe({
      next: (response) => {
        console.log("hi");
        console.log(response);

        this.decodedToken = jwtDecode(localStorage.getItem(this.tokenKey)!);
        console.log(this.decodedToken);
        console.log('rollar kelishi kere');
        for (let index = 0; index < this.decodedToken.role.length; index++) {
          console.log(this.decodedToken.role[index]);
          if (this.decodedToken.role[index] == 'Admin') {
            console.log('admin-test');
            console.log(this.decodedToken.role[index]);
            this.router.navigate(['/users']);
          } else if (this.decodedToken.role[index] == 'Student') {
            console.log('student-test');
            console.log(this.decodedToken.role[index]);
            this.router.navigate(['/student-profile']);
          }
        }

        this.matSnackBar.open(response.message, 'Close', {
          duration: 5000,
          horizontalPosition: 'center'
        });
      },
      error: (err) => {
        console.log(err);

        this.matSnackBar.open(err.message, 'Close', {
          duration: 5000,
          horizontalPosition: 'center'
        });
      }
    });
  }
}